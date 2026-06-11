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

package model

import "testing"

func TestDBQuery_GetQuery(t *testing.T) {
	q := &DBQuery{
		ID:            "TEST_QUERY",
		Query:         "SELECT * FROM t WHERE id = ?",
		PostgresQuery: "SELECT * FROM t WHERE id = $1",
		SQLiteQuery:   "SELECT * FROM t WHERE id = ?",
	}

	cases := []struct {
		name   string
		dbType string
		want   string
	}{
		{name: "mysql uses default query", dbType: "mysql", want: q.Query},
		{name: "empty string falls back to default", dbType: "", want: q.Query},
		{name: "unknown type falls back to default", dbType: "oracle", want: q.Query},
		{name: "postgres uses postgres variant", dbType: "postgres", want: q.PostgresQuery},
		{name: "sqlite uses sqlite variant", dbType: "sqlite", want: q.SQLiteQuery},
		{name: "sqlite3 alias uses sqlite variant", dbType: "sqlite3", want: q.SQLiteQuery},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := q.GetQuery(tc.dbType)
			if got != tc.want {
				t.Errorf("GetQuery(%q) = %q, want %q", tc.dbType, got, tc.want)
			}
		})
	}
}

func TestDBQuery_GetQuery_FallbackWhenVariantEmpty(t *testing.T) {
	// When postgres/sqlite variants are not set, all DB types must fall back to the default.
	q := &DBQuery{
		ID:    "FALLBACK_QUERY",
		Query: "SELECT 1",
		// PostgresQuery and SQLiteQuery intentionally left empty.
	}

	for _, dbType := range []string{"postgres", "sqlite", "sqlite3", "mysql", ""} {
		t.Run("fallback for dbType="+dbType, func(t *testing.T) {
			got := q.GetQuery(dbType)
			if got != "SELECT 1" {
				t.Errorf("GetQuery(%q) = %q, want %q", dbType, got, "SELECT 1")
			}
		})
	}
}

func TestDBQuery_GetID(t *testing.T) {
	q := &DBQuery{ID: "MY_QUERY", Query: "SELECT 1"}
	if got := q.GetID(); got != "MY_QUERY" {
		t.Errorf("GetID() = %q, want MY_QUERY", got)
	}
}
