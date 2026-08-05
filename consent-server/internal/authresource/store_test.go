/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package authresource

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// getString
// =============================================================================

func TestGetString(t *testing.T) {
	cases := []struct {
		name     string
		row      map[string]interface{}
		key      string
		expected string
	}{
		{"string value", map[string]interface{}{"k": "hello"}, "k", "hello"},
		{"byte slice value", map[string]interface{}{"k": []byte("world")}, "k", "world"},
		{"missing key returns empty", map[string]interface{}{"other": "v"}, "k", ""},
		{"integer value returns empty", map[string]interface{}{"k": 42}, "k", ""},
		{"nil value returns empty", map[string]interface{}{"k": nil}, "k", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, getString(tc.row, tc.key))
		})
	}
}

// =============================================================================
// getStringPtr
// =============================================================================

func TestGetStringPtr(t *testing.T) {
	cases := []struct {
		name        string
		row         map[string]interface{}
		key         string
		expectNil   bool
		expectValue string
	}{
		{"string value returns pointer", map[string]interface{}{"k": "val"}, "k", false, "val"},
		{"byte slice value returns pointer", map[string]interface{}{"k": []byte("bytes")}, "k", false, "bytes"},
		{"missing key returns nil", map[string]interface{}{}, "k", true, ""},
		{"nil value returns nil", map[string]interface{}{"k": nil}, "k", true, ""},
		{"integer value returns nil", map[string]interface{}{"k": 99}, "k", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := getStringPtr(tc.row, tc.key)
			if tc.expectNil {
				require.Nil(t, p)
			} else {
				require.NotNil(t, p)
				require.Equal(t, tc.expectValue, *p)
			}
		})
	}
}

// =============================================================================
// getInt64
// =============================================================================

func TestGetInt64(t *testing.T) {
	cases := []struct {
		name     string
		row      map[string]interface{}
		key      string
		expected int64
	}{
		{"int64 value", map[string]interface{}{"k": int64(42)}, "k", 42},
		{"int32 value", map[string]interface{}{"k": int32(10)}, "k", 10},
		{"int value", map[string]interface{}{"k": int(7)}, "k", 7},
		{"float64 truncates", map[string]interface{}{"k": float64(3.9)}, "k", 3},
		{"uint8 slice parseable", map[string]interface{}{"k": []uint8("1702800000000")}, "k", 1702800000000},
		{"string parseable", map[string]interface{}{"k": "9876543210"}, "k", 9876543210},
		{"string not parseable returns 0", map[string]interface{}{"k": "not-int"}, "k", 0},
		{"missing key returns 0", map[string]interface{}{}, "k", 0},
		{"nil value returns 0", map[string]interface{}{"k": nil}, "k", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, getInt64(tc.row, tc.key))
		})
	}
}

// =============================================================================
// mapToAuthResource
// =============================================================================

func TestMapToAuthResource_AllFieldsPresent(t *testing.T) {
	userID := "user@example.com"
	resources := `{"accountIds":["acc-1","acc-2"]}`

	row := map[string]interface{}{
		"auth_id":      "auth-001",
		"consent_id":   "consent-001",
		"auth_type":    "authorisation",
		"user_id":      userID,
		"auth_status":  "APPROVED",
		"updated_time": int64(1702800000000),
		"resources":    resources,
		"org_id":       "org-001",
	}

	ar := mapToAuthResource(row)
	require.NotNil(t, ar)
	require.Equal(t, "auth-001", ar.AuthID)
	require.Equal(t, "consent-001", ar.ConsentID)
	require.Equal(t, "authorisation", ar.AuthType)
	require.NotNil(t, ar.UserID)
	require.Equal(t, userID, *ar.UserID)
	require.Equal(t, "APPROVED", ar.AuthStatus)
	require.Equal(t, int64(1702800000000), ar.UpdatedTime)
	require.NotNil(t, ar.Resources)
	require.Equal(t, resources, *ar.Resources)
	require.Equal(t, "org-001", ar.OrgID)
}

func TestMapToAuthResource_NullableFieldsAreNil(t *testing.T) {
	row := map[string]interface{}{
		"auth_id":      "auth-002",
		"consent_id":   "consent-002",
		"auth_type":    "default",
		"user_id":      nil,
		"auth_status":  "CREATED",
		"updated_time": int64(1702800001000),
		"resources":    nil,
		"org_id":       "org-002",
	}

	ar := mapToAuthResource(row)
	require.NotNil(t, ar)
	require.Nil(t, ar.UserID)
	require.Nil(t, ar.Resources)
}

func TestMapToAuthResource_ByteSliceFields(t *testing.T) {
	// Simulate MySQL driver returning []byte for string columns.
	row := map[string]interface{}{
		"auth_id":      []byte("auth-003"),
		"consent_id":   []byte("consent-003"),
		"auth_type":    []byte("re-authorisation"),
		"user_id":      []byte("admin@example.com"),
		"auth_status":  []byte("REJECTED"),
		"updated_time": int64(1702800002000),
		"resources":    []byte(`{"key":"value"}`),
		"org_id":       []byte("org-003"),
	}

	ar := mapToAuthResource(row)
	require.Equal(t, "auth-003", ar.AuthID)
	require.Equal(t, "consent-003", ar.ConsentID)
	require.Equal(t, "re-authorisation", ar.AuthType)
	require.NotNil(t, ar.UserID)
	require.Equal(t, "admin@example.com", *ar.UserID)
	require.Equal(t, "REJECTED", ar.AuthStatus)
	require.NotNil(t, ar.Resources)
	require.Equal(t, `{"key":"value"}`, *ar.Resources)
	require.Equal(t, "org-003", ar.OrgID)
}

func TestMapToAuthResource_UpdatedTimeFromMySQLUint8(t *testing.T) {
	// MySQL can return BIGINT as []uint8 — getInt64 must parse it.
	row := map[string]interface{}{
		"auth_id":      "auth-004",
		"consent_id":   "consent-004",
		"auth_type":    "default",
		"user_id":      nil,
		"auth_status":  "APPROVED",
		"updated_time": []uint8("1702800003000"),
		"resources":    nil,
		"org_id":       "org-004",
	}

	ar := mapToAuthResource(row)
	require.Equal(t, int64(1702800003000), ar.UpdatedTime)
}

// =============================================================================
// authResourceColumns constant
// =============================================================================

func TestAuthResourceColumns_ContainsAllFields(t *testing.T) {
	// Verify every DB column name the mapper reads is present in the shared constant.
	required := []string{
		"AUTH_ID", "CONSENT_ID", "AUTH_TYPE",
		"USER_ID", "AUTH_STATUS", "UPDATED_TIME", "RESOURCES", "ORG_ID",
	}
	for _, col := range required {
		require.True(t, strings.Contains(authResourceColumns, col),
			"authResourceColumns missing column: %s", col)
	}
}

// =============================================================================
// Query constants — smoke-check structure
// =============================================================================

func TestQueryCreateAuthResource_ContainsInsert(t *testing.T) {
	require.Contains(t, QueryCreateAuthResource.Query, "INSERT INTO CONSENT_AUTH_RESOURCE")
	require.NotEmpty(t, QueryCreateAuthResource.PostgresQuery)
}

func TestQueryGetAuthResourceByID_ContainsAuthIDFilter(t *testing.T) {
	require.Contains(t, QueryGetAuthResourceByID.Query, "AUTH_ID")
	require.Contains(t, QueryGetAuthResourceByID.Query, "ORG_ID")
}

func TestQueryUpdateAuthResource_SetsExpectedColumns(t *testing.T) {
	for _, col := range []string{"AUTH_STATUS", "USER_ID", "RESOURCES", "UPDATED_TIME"} {
		require.Contains(t, QueryUpdateAuthResource.Query, col,
			"UPDATE query missing column: %s", col)
	}
}

func TestQueryDeleteAuthResourcesByConsentID_FiltersByConsentAndOrg(t *testing.T) {
	require.Contains(t, QueryDeleteAuthResourcesByConsentID.Query, "CONSENT_ID")
	require.Contains(t, QueryDeleteAuthResourcesByConsentID.Query, "ORG_ID")
}

func TestQueryUpdateAllStatusByConsentID_SetsStatusAndTime(t *testing.T) {
	require.Contains(t, QueryUpdateAllStatusByConsentID.Query, "AUTH_STATUS")
	require.Contains(t, QueryUpdateAllStatusByConsentID.Query, "UPDATED_TIME")
	require.Contains(t, QueryUpdateAllStatusByConsentID.Query, "CONSENT_ID")
}

func TestQueryGetAuthResourcesByConsentIDs_IsDynamic(t *testing.T) {
	// The dynamic stub has an empty Query; it is built at runtime in GetByConsentIDs.
	require.Empty(t, QueryGetAuthResourcesByConsentIDs.Query,
		"dynamic query stub should have an empty Query field")
	require.NotEmpty(t, QueryGetAuthResourcesByConsentIDs.ID)
}
