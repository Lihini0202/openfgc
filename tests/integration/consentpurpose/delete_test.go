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

// TestDeletePurpose covers DELETE /consent-purposes/{purposeId}.
func (ts *PurposeAPITestSuite) TestDeletePurpose() {
	type testCase struct {
		name          string
		setup         func(orgID string) string // returns purposeId
		purposeID     string                    // used when setup is nil
		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		afterDelete   func(orgID, purposeID string)
	}

	cases := []testCase{
		{
			name: "delete existing purpose — 204",
			setup: func(orgID string) string {
				return ts.mustCreatePurpose(orgID, "del-basic")
			},
			wantStatus: http.StatusNoContent,
			afterDelete: func(orgID, purposeID string) {
				statusGet, body := ts.doRequest(http.MethodGet, "/api/v1/consent-purposes/"+purposeID, orgID, nil)
				ts.Equal(http.StatusNotFound, statusGet, "purpose must not be accessible after deletion")
				ts.assertAPIError(body, "CP-4040")
			},
		},
		{
			name: "delete purpose with multiple versions — all versions removed",
			setup: func(orgID string) string {
				id := ts.mustCreatePurpose(orgID, "del-multi-ver")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{})
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{})
				return id
			},
			wantStatus: http.StatusNoContent,
			afterDelete: func(orgID, purposeID string) {
				statusGet, _ := ts.doGetPurpose(orgID, purposeID)
				ts.Equal(http.StatusNotFound, statusGet)
				// All individual versions also gone
				statusV1, _ := ts.doGetPurposeVersion(orgID, purposeID, "v1")
				ts.Equal(http.StatusNotFound, statusV1, "v1 must be gone after purpose deletion")
				statusV2, _ := ts.doGetPurposeVersion(orgID, purposeID, "v2")
				ts.Equal(http.StatusNotFound, statusV2, "v2 must be gone after purpose deletion")
			},
		},
		{
			name:          "delete non-existent purpose — 404 CP-4040",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "CP-4040",
		},
		{
			name: "delete purpose from wrong org — 404 CP-4040",
			setup: func(orgID string) string {
				// Create purpose in orgID, but we'll try to delete it from a different org (static UUID).
				ts.mustCreatePurpose(orgID, "del-wrong-org")
				return "00000000-0000-0000-0000-000000000001" // different ID entirely
			},
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

			status, body := ts.doDeletePurpose(requestOrgID, purposeID)
			ts.Require().Equal(tc.wantStatus, status)

			if tc.wantErrorCode != "" {
				ts.assertAPIError(body, tc.wantErrorCode)
				return
			}

			if tc.afterDelete != nil {
				tc.afterDelete(orgID, purposeID)
			}
		})
	}
}

// TestPurposeVersionLifecycle exercises the full version lifecycle for a single purpose
// in one sequential test. This covers cross-endpoint contracts that individual endpoint
// tests cannot verify.
//
// Flow: create (v1) → GET latest (v1) → create v2 → GET latest (v2) → list (both) →
//
//	delete v1 → v1 gone, v2 intact → delete v2 (last) → purpose gone
func (ts *PurposeAPITestSuite) TestPurposeVersionLifecycle() {
	orgID := freshOrgID()

	// Step 1: Create purpose — v1 is created automatically
	purposeID := ts.mustCreatePurpose(orgID, "lifecycle-purpose")
	ts.T().Logf("Created purpose: %s", purposeID)

	// Step 2: Verify v1 exists and is the latest
	statusGet, v1 := ts.doGetPurpose(orgID, purposeID)
	ts.Require().Equal(http.StatusOK, statusGet)
	ts.Equal("v1", v1.Version)

	// Step 3: Create v2
	v2Resp := ts.mustCreatePurposeVersion(orgID, purposeID, CreatePurposeVersionRequest{
		DisplayName: ptr("Version Two"),
	})
	ts.Equal("v2", v2Resp.Version)

	// Step 4: GET now returns v2 (latest)
	_, latest := ts.doGetPurpose(orgID, purposeID)
	ts.Equal("v2", latest.Version, "GET must return the latest version after v2 is created")

	// Step 5: List versions — both v1 and v2 present in ascending order
	_, versions := ts.doGetPurposeVersions(orgID, purposeID)
	ts.Require().Len(versions.Versions, 2)
	ts.Equal("v1", versions.Versions[0].Version)
	ts.Equal("v2", versions.Versions[1].Version)

	// Step 6: Delete v1
	statusDel, _ := ts.doDeletePurposeVersion(orgID, purposeID, "v1")
	ts.Require().Equal(http.StatusNoContent, statusDel)

	// Step 7: v1 is gone
	statusV1, _ := ts.doGetPurposeVersion(orgID, purposeID, "v1")
	ts.Equal(http.StatusNotFound, statusV1, "v1 must not be accessible after deletion")

	// Step 8: v2 still intact and is still the latest
	statusV2, v2After := ts.doGetPurposeVersion(orgID, purposeID, "v2")
	ts.Equal(http.StatusOK, statusV2)
	ts.Equal("v2", v2After.Version)
	ts.Equal("Version Two", *v2After.DisplayName)

	// Step 9: List versions — only v2 remains
	_, versionsAfter := ts.doGetPurposeVersions(orgID, purposeID)
	ts.Require().Len(versionsAfter.Versions, 1)
	ts.Equal("v2", versionsAfter.Versions[0].Version)

	// Step 10: Delete v2 — this is the last version, so the purpose itself is also removed
	statusDelV2, _ := ts.doDeletePurposeVersion(orgID, purposeID, "v2")
	ts.Require().Equal(http.StatusNoContent, statusDelV2)

	// Step 11: Purpose is completely gone
	statusPurpose, _ := ts.doGetPurpose(orgID, purposeID)
	ts.Equal(http.StatusNotFound, statusPurpose,
		"purpose must be gone after its last version is deleted")
}
