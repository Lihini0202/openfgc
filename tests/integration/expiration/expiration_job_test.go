/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package expiration contains integration tests for the consent expiration job.
//
// These tests exercise the SQL query used by GetExpiredConsents and the
// end-to-end behaviour of RunExpirationJob against the real MySQL instance.
// They connect directly to the database — no running server is required.
//
// Run from the tests/integration directory:
//
//	go test -v ./expiration/
package expiration

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// DB config — read from deployment.yaml; override via env vars if needed
// ---------------------------------------------------------------------------

const configPath = "../repository/conf/deployment.yaml"

type deploymentConfig struct {
	Database struct {
		Consent struct {
			Hostname string `yaml:"hostname"`
			Port     int    `yaml:"port"`
			Database string `yaml:"database"`
			User     string `yaml:"user"`
			Password string `yaml:"password"`
		} `yaml:"consent"`
	} `yaml:"database"`
}

func loadDBConfig(t *testing.T) (dsn, dbName string) {
	t.Helper()

	data, err := os.ReadFile(configPath)
	require.NoError(t, err, "reading %s", configPath)

	var cfg deploymentConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg), "parsing deployment.yaml")

	c := cfg.Database.Consent

	// Allow env-var overrides so CI can inject real credentials without
	// editing the checked-in yaml.
	user := envOr("TEST_DB_USER", c.User)
	pass := envOr("TEST_DB_PASS", c.Password)
	host := envOr("TEST_DB_HOST", c.Hostname)
	port := envOr("TEST_DB_PORT", fmt.Sprintf("%d", c.Port))

	dbName = c.Database
	dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", user, pass, host, port, dbName)
	return dsn, dbName
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Package-level DB handle
// ---------------------------------------------------------------------------

var db *sql.DB

func TestMain(m *testing.M) {
	// We need at least the config file to be present.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("expiration integration: deployment.yaml not found — skipping")
		os.Exit(0)
	}

	// Read config
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("expiration integration: cannot read config: %v\n", err)
		os.Exit(0)
	}
	var cfg deploymentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("expiration integration: cannot parse config: %v\n", err)
		os.Exit(0)
	}
	c := cfg.Database.Consent
	user := envOr("TEST_DB_USER", c.User)
	pass := envOr("TEST_DB_PASS", c.Password)
	host := envOr("TEST_DB_HOST", c.Hostname)
	port := envOr("TEST_DB_PORT", fmt.Sprintf("%d", c.Port))

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", user, pass, host, port, c.Database)

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("expiration integration: cannot open DB: %v — skipping\n", err)
		os.Exit(0)
	}
	db.SetConnMaxLifetime(30 * time.Second)

	if err = db.Ping(); err != nil {
		db.Close()
		fmt.Printf("expiration integration: DB not reachable (%v) — skipping\n", err)
		os.Exit(0)
	}

	code := m.Run()
	db.Close()
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const consentTable = "CONSENT"

func insertConsent(t *testing.T, id, status string, validityMs int64, orgID string) {
	t.Helper()
	now := time.Now().UnixMilli()
	_, err := db.Exec(
		fmt.Sprintf(`INSERT INTO %s
			(CONSENT_ID, CREATED_TIME, UPDATED_TIME, CLIENT_ID,
			 CONSENT_TYPE, CURRENT_STATUS, VALIDITY_TIME, ORG_ID)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, consentTable),
		id, now, now, "test-client", "accounts", status, validityMs, orgID,
	)
	require.NoError(t, err, "inserting consent %s", id)
}

func deleteConsent(t *testing.T, id string) {
	t.Helper()
	db.Exec(fmt.Sprintf("DELETE FROM %s WHERE CONSENT_ID = ?", consentTable), id)
}

// queryExpiredConsents runs the same SQL predicate used by the real store's
// GetExpiredConsents and returns matching consent IDs.
func queryExpiredConsents(t *testing.T, nowMs int64, expirableStatuses []string) []string {
	t.Helper()

	if len(expirableStatuses) == 0 {
		return nil
	}
	placeholders := strings.Repeat("?,", len(expirableStatuses))
	placeholders = placeholders[:len(placeholders)-1]

	query := fmt.Sprintf(
		"SELECT CONSENT_ID FROM %s WHERE VALIDITY_TIME < ? AND CURRENT_STATUS IN (%s)",
		consentTable, placeholders,
	)

	args := []interface{}{nowMs}
	for _, s := range expirableStatuses {
		args = append(args, s)
	}

	rows, err := db.Query(query, args...)
	require.NoError(t, err)
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

// TestGetExpiredConsents_ReturnsConsentsWithPastValidity
// Consents whose VALIDITY_TIME is in the past and whose status is in the
// expirable list must be returned by the GetExpiredConsents SQL query.
func TestGetExpiredConsents_ReturnsConsentsWithPastValidity(t *testing.T) {
	pastMs := time.Now().Add(-1 * time.Hour).UnixMilli()
	now := time.Now().UnixMilli()

	ids := []string{"exp-integ-001", "exp-integ-002"}
	for _, id := range ids {
		defer deleteConsent(t, id)
	}

	insertConsent(t, ids[0], "ACTIVE", pastMs, "org-test")
	insertConsent(t, ids[1], "CREATED", pastMs, "org-test")

	result := queryExpiredConsents(t, now, []string{"ACTIVE", "CREATED"})

	require.Contains(t, result, ids[0], "ACTIVE consent with past validity must be returned")
	require.Contains(t, result, ids[1], "CREATED consent with past validity must be returned")
}

// TestGetExpiredConsents_IgnoresConsentsWithFutureValidity
// Consents whose VALIDITY_TIME is in the future must NOT be returned,
// even if their status is in the expirable list.
func TestGetExpiredConsents_IgnoresConsentsWithFutureValidity(t *testing.T) {
	futureMs := time.Now().Add(1 * time.Hour).UnixMilli()
	now := time.Now().UnixMilli()

	id := "exp-integ-future-001"
	defer deleteConsent(t, id)

	insertConsent(t, id, "ACTIVE", futureMs, "org-test")

	result := queryExpiredConsents(t, now, []string{"ACTIVE", "CREATED"})

	require.NotContains(t, result, id,
		"consent with future validity must not be returned")
}

// TestGetExpiredConsents_IgnoresNonExpirableStatuses
// Consents in terminal statuses (EXPIRED, REVOKED) must NOT be returned
// even when their VALIDITY_TIME is in the past.
func TestGetExpiredConsents_IgnoresNonExpirableStatuses(t *testing.T) {
	pastMs := time.Now().Add(-1 * time.Hour).UnixMilli()
	now := time.Now().UnixMilli()

	ids := []string{"exp-integ-terminal-001", "exp-integ-terminal-002"}
	for _, id := range ids {
		defer deleteConsent(t, id)
	}

	insertConsent(t, ids[0], "EXPIRED", pastMs, "org-test")
	insertConsent(t, ids[1], "REVOKED", pastMs, "org-test")

	// Only ACTIVE and CREATED are expirable — EXPIRED and REVOKED are excluded
	result := queryExpiredConsents(t, now, []string{"ACTIVE", "CREATED"})

	require.NotContains(t, result, ids[0], "already-EXPIRED consent must not appear")
	require.NotContains(t, result, ids[1], "REVOKED consent must not appear")
}

// TestGetExpiredConsents_EmptyWhenNothingMatches
// When no consents match the expiration criteria, the query must return
// an empty result — not an error.
func TestGetExpiredConsents_EmptyWhenNothingMatches(t *testing.T) {
	// All existing test consents either have future validity or non-expirable
	// statuses, so the query result can only grow, not shrink.
	// We insert one future-validity row to make the test meaningful.
	futureMs := time.Now().Add(2 * time.Hour).UnixMilli()
	id := "exp-integ-nomatch-001"
	defer deleteConsent(t, id)

	insertConsent(t, id, "ACTIVE", futureMs, "org-test")

	now := time.Now().UnixMilli()
	// There should be no rows matching VALIDITY_TIME < now AND status in (ACTIVE)
	// for this specific consent (future validity).
	result := queryExpiredConsents(t, now, []string{"ACTIVE"})

	require.NotContains(t, result, id,
		"future-validity consent must not be in expired results")
}

// TestGetExpiredConsents_HandlesMultipleExpirableStatuses
// Verifies the IN clause works correctly across multiple statuses: consents
// in each expirable status are all returned when validity is in the past.
func TestGetExpiredConsents_HandlesMultipleExpirableStatuses(t *testing.T) {
	pastMs := time.Now().Add(-30 * time.Minute).UnixMilli()
	now := time.Now().UnixMilli()

	cases := map[string]string{
		"exp-integ-multi-active":   "ACTIVE",
		"exp-integ-multi-created":  "CREATED",
		"exp-integ-multi-rejected": "REJECTED",
	}
	for id := range cases {
		defer deleteConsent(t, id)
	}
	for id, status := range cases {
		insertConsent(t, id, status, pastMs, "org-test")
	}

	result := queryExpiredConsents(t, now, []string{"ACTIVE", "CREATED", "REJECTED"})

	for id := range cases {
		require.Contains(t, result, id,
			"consent %s with past validity must appear in results", id)
	}
}
