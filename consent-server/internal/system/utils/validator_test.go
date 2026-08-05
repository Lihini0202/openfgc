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

import (
	"strings"
	"testing"
)

func TestValidateOrgID(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid org ID", input: "org-123", wantErr: false},
		{name: "empty string", input: "", wantErr: true},
		{name: "exactly 255 chars — valid", input: strings.Repeat("a", 255), wantErr: false},
		{name: "256 chars — too long", input: strings.Repeat("a", 256), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOrgID(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateOrgID(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateRequired(t *testing.T) {
	cases := []struct {
		name      string
		fieldName string
		value     string
		wantErr   bool
	}{
		{name: "non-empty value", fieldName: "consentID", value: "abc", wantErr: false},
		{name: "empty value", fieldName: "consentID", value: "", wantErr: true},
		{name: "error message includes field name", fieldName: "purposeID", value: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRequired(tc.fieldName, tc.value)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRequired(%q, %q) error = %v, wantErr %v", tc.fieldName, tc.value, err, tc.wantErr)
			}
			if err != nil && tc.fieldName != "" {
				if !strings.Contains(err.Error(), tc.fieldName) {
					t.Errorf("expected error message to contain field name %q, got %q", tc.fieldName, err.Error())
				}
			}
		})
	}
}

func TestValidateUUID(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid v4 UUID", input: "550e8400-e29b-41d4-a716-446655440000", wantErr: false},
		{name: "empty string", input: "", wantErr: true},
		{name: "missing hyphens", input: "550e8400e29b41d4a716446655440000", wantErr: true},
		{name: "wrong length", input: "550e8400-e29b-41d4-a716", wantErr: true},
		{name: "non-hex chars", input: "gggggggg-e29b-41d4-a716-446655440000", wantErr: true},
		{name: "all zeros", input: "00000000-0000-0000-0000-000000000000", wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUUID(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateUUID(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateConsentID(t *testing.T) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid UUID consent ID", input: validUUID, wantErr: false},
		{name: "empty consent ID", input: "", wantErr: true},
		{name: "exactly 100 chars but not UUID — invalid format", input: strings.Repeat("a", 100), wantErr: true},
		{name: "101-char string — too long (checked before UUID format)", input: strings.Repeat("a", 101), wantErr: true},
		{name: "valid UUID but 37 chars (one extra) — UUID format fails", input: validUUID + "x", wantErr: true},
		{name: "non-UUID string", input: "not-a-uuid", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConsentID(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateConsentID(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}
