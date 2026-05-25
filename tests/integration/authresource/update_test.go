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
	"encoding/json"
	"net/http"
)

// TestUpdateAuthResource covers PUT /consents/{consentId}/authorizations/{authorizationId}.
//
// Isolation: each sub-test gets a fresh org, a dedicated consent, and a dedicated auth resource.
func (ts *AuthResourceAPITestSuite) TestUpdateAuthResource() {
	type testCase struct {
		name string

		// setup creates pre-conditions and returns (consentID, authID, update request body).
		// Use raw string as body for parse-error cases.
		setup func(orgID string) (consentID, authID string, body any)

		// useAltOrg sends the PUT request under a different fresh org (cross-org tests).
		useAltOrg bool

		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		checkResult   func(orgID, consentID string, resp *AuthResourceResponse)
	}

	cases := []testCase{

		// -----------------------------------------------------------------------
		// Field updates
		// -----------------------------------------------------------------------
		{
			name: "update status — new status returned",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-status")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{Status: "CREATED"})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "APPROVED"}
			},
			wantStatus: http.StatusOK,
			checkResult: func(_, _ string, resp *AuthResourceResponse) {
				ts.assertAuthResourceResponse(resp)
				ts.Equal("APPROVED", resp.Status)
			},
		},
		{
			name: "update type — new type returned, other fields preserved",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-type")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{
					Type: "accounts", Status: "APPROVED",
				})
				return consentID, ar.ID, AuthResourceUpdateRequest{Type: "payments"}
			},
			wantStatus: http.StatusOK,
			checkResult: func(_, _ string, resp *AuthResourceResponse) {
				ts.Equal("payments", resp.Type)
				ts.Equal("APPROVED", resp.Status, "status must not change when only type is updated")
			},
		},
		{
			name: "update userId — new userId returned",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-user")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{
					UserID: strPtr("original-user"),
				})
				return consentID, ar.ID, AuthResourceUpdateRequest{UserID: strPtr("updated-user")}
			},
			wantStatus: http.StatusOK,
			checkResult: func(_, _ string, resp *AuthResourceResponse) {
				ts.Require().NotNil(resp.UserID)
				ts.Equal("updated-user", *resp.UserID)
			},
		},
		{
			name: "update resources — new resources returned",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-res")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{
					Resources: "original",
				})
				return consentID, ar.ID, AuthResourceUpdateRequest{
					Resources: map[string]interface{}{"newKey": "newValue"},
				}
			},
			wantStatus: http.StatusOK,
			checkResult: func(_, _ string, resp *AuthResourceResponse) {
				ts.Require().NotNil(resp.Resources)
			},
		},

		// -----------------------------------------------------------------------
		// Consent status derivation on update
		// -----------------------------------------------------------------------
		{
			name: "updating auth status from CREATED to APPROVED — consent becomes ACTIVE",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-derive")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{Status: "CREATED"})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "APPROVED"}
			},
			wantStatus: http.StatusOK,
			checkResult: func(orgID, consentID string, _ *AuthResourceResponse) {
				ts.Equal("ACTIVE", ts.getConsentStatus(orgID, consentID),
					"consent must become ACTIVE when its only auth is updated to APPROVED")
			},
		},
		{
			name: "updating auth status from APPROVED to REJECTED — consent becomes REJECTED",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-reject")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{Status: "APPROVED"})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "REJECTED"}
			},
			wantStatus: http.StatusOK,
			checkResult: func(orgID, consentID string, _ *AuthResourceResponse) {
				ts.Equal("REJECTED", ts.getConsentStatus(orgID, consentID),
					"consent must become REJECTED when its only auth is updated to REJECTED")
			},
		},

		// -----------------------------------------------------------------------
		// Validation errors
		// -----------------------------------------------------------------------
		{
			name: "empty body — no fields provided → 400 AR-4002",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-empty")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{})
				return consentID, ar.ID, AuthResourceUpdateRequest{}
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "AR-4002",
		},
		{
			name: "system-reserved status 'SYS_EXPIRED' → 400 AR-4002",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-sysexp")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "SYS_EXPIRED"}
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "AR-4002",
		},
		{
			name: "system-reserved status 'SYS_REVOKED' → 400 AR-4002",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-sysrev")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "SYS_REVOKED"}
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "AR-4002",
		},
		{
			name: "malformed JSON body → 400 AR-4001",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-json")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{})
				return consentID, ar.ID, `{bad-json`
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "AR-4001",
		},

		// -----------------------------------------------------------------------
		// Not found
		// -----------------------------------------------------------------------
		{
			name: "unknown auth ID → 404 AR-4040",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-nf")
				return consentID, "00000000-0000-0000-0000-000000000000",
					AuthResourceUpdateRequest{Status: "APPROVED"}
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "AR-4040",
		},

		// -----------------------------------------------------------------------
		// Cross-org isolation
		// -----------------------------------------------------------------------
		{
			name: "auth created under org A — updating with org B's header → 404 AR-4040",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-org")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "APPROVED"}
			},
			useAltOrg:     true,
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "AR-4040",
		},

		// -----------------------------------------------------------------------
		// Header errors
		// -----------------------------------------------------------------------
		{
			name: "missing org-id header → 400 AR-4007",
			setup: func(orgID string) (string, string, any) {
				consentID := ts.mustCreateConsent(orgID, "grp-ar-upd-hdr")
				ar := ts.mustCreateAuthResource(orgID, consentID, AuthResourceCreateRequest{})
				return consentID, ar.ID, AuthResourceUpdateRequest{Status: "APPROVED"}
			},
			omitOrgID:     true,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "AR-4007",
		},
	}

	for _, tc := range cases {
		tc := tc
		ts.Run(tc.name, func() {
			orgID := freshOrgID()
			consentID, authID, body := tc.setup(orgID)

			orgForReq := orgID
			switch {
			case tc.omitOrgID:
				orgForReq = ""
			case tc.useAltOrg:
				orgForReq = freshOrgID()
			}

			status, respBody := ts.doRequest(
				http.MethodPut,
				"/api/v1/consents/"+consentID+"/authorizations/"+authID,
				orgForReq,
				body,
			)

			ts.Equal(tc.wantStatus, status)
			if tc.wantErrorCode != "" {
				ts.assertAPIError(respBody, tc.wantErrorCode)
			} else if tc.checkResult != nil {
				var resp AuthResourceResponse
				ts.Require().NoError(json.Unmarshal(respBody, &resp), "unmarshal response: %s", respBody)
				tc.checkResult(orgID, consentID, &resp)
			}
		})
	}
}
