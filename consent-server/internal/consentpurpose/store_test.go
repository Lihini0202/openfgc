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

package consentpurpose

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPurposeStore(t *testing.T) {
	s := NewPurposeStore()
	require.NotNil(t, s)
}

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
	t.Run("string value returns pointer", func(t *testing.T) {
		p := getStringPtr(map[string]interface{}{"k": "val"}, "k")
		require.NotNil(t, p)
		require.Equal(t, "val", *p)
	})

	t.Run("byte slice value returns pointer", func(t *testing.T) {
		p := getStringPtr(map[string]interface{}{"k": []byte("val")}, "k")
		require.NotNil(t, p)
		require.Equal(t, "val", *p)
	})

	t.Run("missing key returns nil", func(t *testing.T) {
		require.Nil(t, getStringPtr(map[string]interface{}{}, "k"))
	})

	t.Run("nil value returns nil", func(t *testing.T) {
		require.Nil(t, getStringPtr(map[string]interface{}{"k": nil}, "k"))
	})

	t.Run("integer value returns nil", func(t *testing.T) {
		require.Nil(t, getStringPtr(map[string]interface{}{"k": 99}, "k"))
	})
}

// =============================================================================
// getInt64
// =============================================================================

func TestGetInt64(t *testing.T) {
	require.Equal(t, int64(42), getInt64(map[string]interface{}{"k": int64(42)}, "k"))
	require.Equal(t, int64(0), getInt64(map[string]interface{}{"k": "not-int"}, "k"))
	require.Equal(t, int64(0), getInt64(map[string]interface{}{}, "k"))
	require.Equal(t, int64(0), getInt64(nil, "k"))
}

// =============================================================================
// getInt
// =============================================================================

func TestGetInt(t *testing.T) {
	require.Equal(t, 3, getInt(map[string]interface{}{"k": int64(3)}, "k"))
	require.Equal(t, 5, getInt(map[string]interface{}{"k": int32(5)}, "k"))
	require.Equal(t, 7, getInt(map[string]interface{}{"k": uint32(7)}, "k"))
	require.Equal(t, 0, getInt(map[string]interface{}{"k": "nope"}, "k"))
	require.Equal(t, 0, getInt(map[string]interface{}{}, "k"))
}

// =============================================================================
// getBool
// =============================================================================

func TestGetBool(t *testing.T) {
	// bool driver
	require.True(t, getBool(map[string]interface{}{"k": true}, "k"))
	require.False(t, getBool(map[string]interface{}{"k": false}, "k"))
	// int64 driver (MySQL TINYINT(1))
	require.True(t, getBool(map[string]interface{}{"k": int64(1)}, "k"))
	require.False(t, getBool(map[string]interface{}{"k": int64(0)}, "k"))
	// uint8 driver
	require.True(t, getBool(map[string]interface{}{"k": uint8(1)}, "k"))
	require.False(t, getBool(map[string]interface{}{"k": uint8(0)}, "k"))
	// int32 driver
	require.True(t, getBool(map[string]interface{}{"k": int32(1)}, "k"))
	// missing key
	require.False(t, getBool(map[string]interface{}{}, "k"))
}

// =============================================================================
// mapToPurposeVersion
// =============================================================================

func TestMapToPurposeVersion(t *testing.T) {
	t.Run("nil row returns nil", func(t *testing.T) {
		require.Nil(t, mapToPurposeVersion(nil))
	})

	t.Run("complete row", func(t *testing.T) {
		desc := "test desc"
		disp := "Display Name"
		row := map[string]interface{}{
			"version_id":   "vid-1",
			"id":           "pid-1",
			"name":         "Marketing",
			"group_id":     "grp-1",
			"version":      int64(2),
			"display_name": disp,
			"description":  desc,
			"created_time": int64(1234567890),
			"org_id":       "org-1",
		}
		pv := mapToPurposeVersion(row)
		require.NotNil(t, pv)
		require.Equal(t, "vid-1", pv.VersionID)
		require.Equal(t, "pid-1", pv.ID)
		require.Equal(t, "Marketing", pv.Name)
		require.Equal(t, "grp-1", pv.GroupID)
		require.Equal(t, 2, pv.VersionNum)
		require.NotNil(t, pv.DisplayName)
		require.Equal(t, disp, *pv.DisplayName)
		require.NotNil(t, pv.Description)
		require.Equal(t, desc, *pv.Description)
		require.Equal(t, int64(1234567890), pv.CreatedTime)
		require.Equal(t, "org-1", pv.OrgID)
	})

	t.Run("nil optional fields", func(t *testing.T) {
		row := map[string]interface{}{
			"version_id":   "vid-1",
			"id":           "pid-1",
			"name":         "Simple",
			"group_id":     "grp-1",
			"version":      int64(1),
			"display_name": nil,
			"description":  nil,
			"created_time": int64(0),
			"org_id":       "org-1",
		}
		pv := mapToPurposeVersion(row)
		require.Nil(t, pv.DisplayName)
		require.Nil(t, pv.Description)
	})
}

// =============================================================================
// mapToPurposeMappedElement
// =============================================================================

func TestMapToPurposeMappedElement(t *testing.T) {
	row := map[string]interface{}{
		"element_version_id": "ev-1",
		"element_id":         "elem-1",
		"name":               "email",
		"namespace":          "default",
		"version":            int64(3),
		"mandatory":          true,
	}
	elem := mapToPurposeMappedElement(row)
	require.Equal(t, "ev-1", elem.ElementVersionID)
	require.Equal(t, "elem-1", elem.ElementID)
	require.Equal(t, "email", elem.Name)
	require.Equal(t, "default", elem.Namespace)
	require.Equal(t, 3, elem.VersionNum)
	require.True(t, elem.Mandatory)
}

func TestMapToPurposeMappedElement_FalseManatody(t *testing.T) {
	row := map[string]interface{}{
		"element_version_id": "ev-2",
		"element_id":         "elem-2",
		"name":               "phone",
		"namespace":          "default",
		"version":            int64(1),
		"mandatory":          false,
	}
	elem := mapToPurposeMappedElement(row)
	require.False(t, elem.Mandatory)
}
