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

// Combined integration tests for consent expiration and scheduler behavior.
// These were previously split across tests/integration/expiration and
// tests/integration/scheduler; moving them here simplifies running consent
// integration scenarios.

package consent

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var db *sql.DB

func TestMain(m *testing.M) {
	// Skip if config not present.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Println("consent integration: deployment.yaml not found — skipping")
		os.Exit(0)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("consent integration: cannot read config: %v\n", err)
		os.Exit(0)
	}
	var cfg deploymentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("consent integration: cannot parse config: %v\n", err)
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
		fmt.Printf("consent integration: cannot open DB: %v — skipping\n", err)
		os.Exit(0)
	}
	db.SetConnMaxLifetime(30 * time.Second)

	if err = db.Ping(); err != nil {
		db.Close()
		fmt.Printf("consent integration: DB not reachable (%v) — skipping\n", err)
		os.Exit(0)
	}

	code := m.Run()
	db.Close()
	os.Exit(code)
}

// Helpers
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
	// Child rows first to avoid FK constraint violations.
	db.Exec("DELETE FROM CONSENT_STATUS_AUDIT WHERE CONSENT_ID = ?", id)
	db.Exec("DELETE FROM CONSENT WHERE CONSENT_ID = ?", id)
}

// queryExpiredConsents runs the same SQL predicate used by the real store's
// GetExpiredConsents and returns matching consent IDs.
func queryExpiredConsents(t *testing.T, currentTimeMs int64, expirableStatuses []string) []string {
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

	args := []interface{}{currentTimeMs}
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

func queryConsentStatus(t *testing.T, id string) string {
	t.Helper()
	var status string
	err := db.QueryRow(
		"SELECT CURRENT_STATUS FROM CONSENT WHERE CONSENT_ID = ?", id,
	).Scan(&status)
	require.NoError(t, err, "querying status for consent %s", id)
	return status
}

func queryAuditCount(t *testing.T, id string) int {
	t.Helper()
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM CONSENT_STATUS_AUDIT WHERE CONSENT_ID = ?", id,
	).Scan(&count)
	require.NoError(t, err)
	return count
}

// pollUntilStatus polls every interval until status matches want or timeout exceeded.
func pollUntilStatus(t *testing.T, id, want string, timeout, interval time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got string
	for time.Now().Before(deadline) {
		got = queryConsentStatus(t, id)
		if got == want {
			return got
		}
		time.Sleep(interval)
	}
	return got
}

// Expiration Integration Tests

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

func TestGetExpiredConsents_EmptyWhenNothingMatches(t *testing.T) {
	futureMs := time.Now().Add(2 * time.Hour).UnixMilli()
	id := "exp-integ-nomatch-001"
	defer deleteConsent(t, id)

	insertConsent(t, id, "ACTIVE", futureMs, "org-test")

	now := time.Now().UnixMilli()
	result := queryExpiredConsents(t, now, []string{"ACTIVE"})

	require.NotContains(t, result, id,
		"future-validity consent must not be in expired results")
}

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

// Scheduler integration tests

const (
	pollInterval = 500 * time.Millisecond
)

func TestScheduler_ExpiresActiveConsent_WhenValidityTimePassed(t *testing.T) {
	id := "sched-integ-expire-001"
	deleteConsent(t, id)
	defer deleteConsent(t, id)

	expiresAt := time.Now().Add(30 * time.Second).UnixMilli()
	insertConsent(t, id, "ACTIVE", expiresAt, "ORG-001")

	require.Equal(t, "ACTIVE", queryConsentStatus(t, id),
		"consent must start as ACTIVE before scheduler fires")

	finalStatus := pollUntilStatus(t, id, "EXPIRED", 60*time.Second, pollInterval)

	assert.Equal(t, "EXPIRED", finalStatus,
		"scheduler must flip CURRENT_STATUS to EXPIRED after validity time passes")

	assert.GreaterOrEqual(t, queryAuditCount(t, id), 1,
		"at least one CONSENT_STATUS_AUDIT row must be written on expiration")
}
