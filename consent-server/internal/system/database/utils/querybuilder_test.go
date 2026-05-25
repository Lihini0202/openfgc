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

package utils

import "testing"

func TestConvertToPostgresParams(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no placeholders — query unchanged",
			input: "SELECT * FROM t",
			want:  "SELECT * FROM t",
		},
		{
			name:  "single placeholder",
			input: "SELECT * FROM t WHERE id = ?",
			want:  "SELECT * FROM t WHERE id = $1",
		},
		{
			name:  "two placeholders numbered in order",
			input: "SELECT * FROM t WHERE a = ? AND b = ?",
			want:  "SELECT * FROM t WHERE a = $1 AND b = $2",
		},
		{
			name:  "three placeholders",
			input: "INSERT INTO t (a, b, c) VALUES (?, ?, ?)",
			want:  "INSERT INTO t (a, b, c) VALUES ($1, $2, $3)",
		},
		{
			name:  "empty query",
			input: "",
			want:  "",
		},
		{
			name:  "question mark inside a string literal — still replaced (no SQL parsing)",
			input: "SELECT '?' FROM t WHERE id = ?",
			want:  "SELECT '$1' FROM t WHERE id = $2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ConvertToPostgresParams(tc.input)
			if got != tc.want {
				t.Errorf("ConvertToPostgresParams(%q)\n  got  %q\n  want %q", tc.input, got, tc.want)
			}
		})
	}
}
