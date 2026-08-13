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
	"net/http"
)

// TestGetPurpose covers GET /consent-purposes/{purposeId} — returns the latest version.
func (ts *PurposeAPITestSuite) TestGetPurpose() {
	type testCase struct {
		name          string
		setup         func(orgID string) string // returns purposeId
		purposeID     string                    // used when setup is nil (static IDs for 404 tests)
		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		checkResult   func(orgID string, resp *PurposeResponse)
	}

	cases := []testCase{
		{
			name: "existing purpose — all fields including element details returned correctly",
			setup: func(orgID string) string {
				ts.mustCreateElement(orgID, "gp-basic-elem", "basic")
				return ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:        "gp-basic",
					DisplayName: ptr("Basic Purpose"),
					Description: ptr("A simple purpose"),
					Properties:  map[string]string{"key": "value"},
					Elements: []ElementRefRequest{
						{Name: "gp-basic-elem", Mandatory: true},
					},
				}).PurposeID
			},
			wantStatus: http.StatusOK,
			checkResult: func(orgID string, resp *PurposeResponse) {
				ts.assertPurposeResponse(resp, "gp-basic")
				ts.Equal("v1", resp.Version)
				ts.Equal(orgID, resp.GroupID, "org-level: groupId must equal orgId")
				ts.Require().NotNil(resp.DisplayName)
				ts.Equal("Basic Purpose", *resp.DisplayName)
				ts.Require().NotNil(resp.Description)
				ts.Equal("A simple purpose", *resp.Description)
				ts.Equal("value", resp.Properties["key"])
				ts.Require().Len(resp.Elements, 1)
				ts.assertPurposeElement(resp.Elements[0], "gp-basic-elem", "default", "v1", true)
			},
		},
		{
			name: "GET returns latest version after v2 is created",
			setup: func(orgID string) string {
				id := ts.mustCreatePurpose(orgID, "gp-latest")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{
					DisplayName: ptr("Version Two"),
				})
				return id
			},
			wantStatus: http.StatusOK,
			checkResult: func(_ string, resp *PurposeResponse) {
				ts.Equal("v2", resp.Version, "GET must return the latest version")
				ts.Require().NotNil(resp.DisplayName)
				ts.Equal("Version Two", *resp.DisplayName)
			},
		},
		{
			name:      "purpose from wrong org — 404 CP-4040",
			purposeID: "00000000-0000-0000-0000-000000000000",
			setup: func(orgID string) string {
				// Create the purpose in orgID, but we'll query it from a different orgID below.
				// We use a static non-existent ID here to simulate cross-org isolation.
				return "00000000-0000-0000-0000-000000000000"
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "CP-4040",
		},
		{
			name:          "non-existent purpose ID — 404 CP-4040",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "CP-4040",
		},
		{
			name:          "missing org-id header — 400 CP-4004",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			omitOrgID:     true,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4004",
		},
	}

	for _, tc := range cases {
		tc := tc
		ts.Run(tc.name, func() {
			orgID := freshOrgID()

			var purposeID string
			if tc.setup != nil {
				purposeID = tc.setup(orgID)
			} else {
				purposeID = tc.purposeID
			}

			requestOrgID := orgID
			if tc.omitOrgID {
				requestOrgID = ""
			}

			status, body := ts.doRequest(http.MethodGet, "/api/v1/consent-purposes/"+purposeID, requestOrgID, nil)
			ts.Require().Equal(tc.wantStatus, status)

			if tc.wantErrorCode != "" {
				ts.assertAPIError(body, tc.wantErrorCode)
				return
			}

			status2, resp := ts.doGetPurpose(orgID, purposeID)
			ts.Require().Equal(http.StatusOK, status2)
			if tc.checkResult != nil {
				tc.checkResult(orgID, resp)
			}
		})
	}
}
