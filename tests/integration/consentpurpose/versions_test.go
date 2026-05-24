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
	"encoding/json"
	"net/http"
)

// TestListPurposeVersions covers GET /consent-purposes/{purposeId}/versions.
func (ts *PurposeAPITestSuite) TestListPurposeVersions() {
	type testCase struct {
		name          string
		setup         func(orgID string) string // returns purposeId
		purposeID     string                    // used when setup is nil
		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		checkResult   func(resp *PurposeVersionListResponse)
	}

	cases := []testCase{
		{
			name: "single version — returns list with one entry",
			setup: func(orgID string) string {
				return ts.mustCreatePurpose(orgID, "lv-single")
			},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeVersionListResponse) {
				ts.Equal("lv-single", resp.Name)
				ts.NotEmpty(resp.PurposeID)
				ts.NotEmpty(resp.GroupID)
				ts.Require().Len(resp.Versions, 1)
				ts.Equal("v1", resp.Versions[0].Version)
				ts.Greater(resp.Versions[0].CreatedTime, int64(0))
			},
		},
		{
			name: "multiple versions — all returned in ascending version order",
			setup: func(orgID string) string {
				id := ts.mustCreatePurpose(orgID, "lv-multi")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{DisplayName: ptr("V2")})
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{DisplayName: ptr("V3")})
				return id
			},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeVersionListResponse) {
				ts.Require().Len(resp.Versions, 3)
				ts.Equal("v1", resp.Versions[0].Version)
				ts.Equal("v2", resp.Versions[1].Version)
				ts.Equal("v3", resp.Versions[2].Version)
			},
		},
		{
			name: "purpose-level fields hoisted to response root",
			setup: func(orgID string) string {
				return ts.mustCreatePurposeWith(orgID, "my-group", CreatePurposeRequest{
					Name:        "lv-meta",
					DisplayName: ptr("Metadata Test"),
				}).PurposeID
			},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeVersionListResponse) {
				ts.Equal("lv-meta", resp.Name)
				ts.Equal("my-group", resp.GroupID)
				ts.NotEmpty(resp.PurposeID)
			},
		},
		{
			name:          "non-existent purpose — 404 CP-4040",
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

			path := "/api/v1/consent-purposes/" + purposeID + "/versions"
			status, body := ts.doRequest(http.MethodGet, path, requestOrgID, nil)
			ts.Require().Equal(tc.wantStatus, status)

			if tc.wantErrorCode != "" {
				ts.assertAPIError(body, tc.wantErrorCode)
				return
			}

			var resp PurposeVersionListResponse
			ts.Require().NoError(json.Unmarshal(body, &resp))
			if tc.checkResult != nil {
				tc.checkResult(&resp)
			}
		})
	}
}

// TestCreatePurposeVersion covers POST /consent-purposes/{purposeId}/versions.
//
// The server requires at least one element on every version create.
// Happy-path cases use buildBody to create any required elements in the same org
// before building the request. Error cases that fail before element look-up use rawBody.
func (ts *PurposeAPITestSuite) TestCreatePurposeVersion() {
	type testCase struct {
		name      string
		setup     func(orgID string) string // returns purposeId
		purposeID string

		// buildBody creates required elements and returns the request body.
		buildBody func(orgID string) any
		// rawBody is used for validation errors that fire before element look-up.
		rawBody string

		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		checkResult   func(resp *PurposeResponse)
	}

	cases := []testCase{
		{
			name: "creates v2 — version auto-increments",
			setup: func(orgID string) string {
				return ts.mustCreatePurpose(orgID, "cv-auto-inc")
			},
			buildBody: func(orgID string) any {
				return CreatePurposeVersionRequest{
					DisplayName: ptr("Second Version"),
					Elements:    []ElementRefRequest{ts.nextAutoElem(orgID)},
				}
			},
			wantStatus: http.StatusCreated,
			checkResult: func(resp *PurposeResponse) {
				ts.assertPurposeResponse(resp, "cv-auto-inc")
				ts.Equal("v2", resp.Version)
				ts.Require().NotNil(resp.DisplayName)
				ts.Equal("Second Version", *resp.DisplayName)
			},
		},
		{
			name: "creates v3 after v2 — continues incrementing",
			setup: func(orgID string) string {
				id := ts.mustCreatePurpose(orgID, "cv-triple")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{})
				return id
			},
			buildBody: func(orgID string) any {
				return CreatePurposeVersionRequest{
					Description: ptr("Third"),
					Elements:    []ElementRefRequest{ts.nextAutoElem(orgID)},
				}
			},
			wantStatus: http.StatusCreated,
			checkResult: func(resp *PurposeResponse) {
				ts.Equal("v3", resp.Version)
			},
		},
		{
			name: "immutable fields inherited — name and groupId unchanged",
			setup: func(orgID string) string {
				return ts.mustCreatePurposeWith(orgID, "stable-grp", CreatePurposeRequest{
					Name: "cv-immutable",
				}).PurposeID
			},
			buildBody: func(orgID string) any {
				return CreatePurposeVersionRequest{
					DisplayName: ptr("New display"),
					Elements:    []ElementRefRequest{ts.nextAutoElem(orgID)},
				}
			},
			wantStatus: http.StatusCreated,
			checkResult: func(resp *PurposeResponse) {
				ts.Equal("cv-immutable", resp.Name, "name must be inherited")
				ts.Equal("stable-grp", resp.GroupID, "groupId must be inherited")
			},
		},
		{
			name: "new version with explicit element — name, namespace, version, mandatory all correct",
			setup: func(orgID string) string {
				ts.mustCreateElement(orgID, "cv-ver-elem", "basic")
				return ts.mustCreatePurpose(orgID, "cv-with-elem")
			},
			buildBody: func(_ string) any {
				return CreatePurposeVersionRequest{
					Elements: []ElementRefRequest{{Name: "cv-ver-elem", Mandatory: true}},
				}
			},
			wantStatus: http.StatusCreated,
			checkResult: func(resp *PurposeResponse) {
				ts.Require().Len(resp.Elements, 1)
				ts.assertPurposeElement(resp.Elements[0], "cv-ver-elem", "default", "v1", true)
			},
		},
		{
			name: "new version with properties — stored and returned",
			setup: func(orgID string) string {
				return ts.mustCreatePurpose(orgID, "cv-props")
			},
			buildBody: func(orgID string) any {
				return CreatePurposeVersionRequest{
					Properties: map[string]string{"reviewed": "true"},
					Elements:   []ElementRefRequest{ts.nextAutoElem(orgID)},
				}
			},
			wantStatus: http.StatusCreated,
			checkResult: func(resp *PurposeResponse) {
				ts.Equal("true", resp.Properties["reviewed"])
			},
		},
		// -----------------------------------------------------------------------
		// Errors that fire before element look-up — no elements needed in body.
		// -----------------------------------------------------------------------
		{
			// Purpose not found check fires before element validation.
			name:          "non-existent purpose — 404 CP-4040",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			rawBody:       `{"elements":[{"name":"e"}]}`,
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "CP-4040",
		},
		{
			name:          "malformed JSON body — 400 CP-4001",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			rawBody:       `{bad json`,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4001",
		},
		{
			// Version format parse error fires in handler before service call.
			name:          "invalid element version format — 400 CP-4001",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			rawBody:       `{"elements":[{"name":"e","version":"bad"}]}`,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4001",
		},
		{
			name:          "missing org-id header — 400 CP-4004",
			purposeID:     "00000000-0000-0000-0000-000000000000",
			rawBody:       `{"elements":[{"name":"e"}]}`,
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

			var body any
			if tc.buildBody != nil {
				body = tc.buildBody(orgID)
			} else {
				body = tc.rawBody
			}

			path := "/api/v1/consent-purposes/" + purposeID + "/versions"
			status, respBody := ts.doRequest(http.MethodPost, path, requestOrgID, body)
			ts.Require().Equal(tc.wantStatus, status)

			if tc.wantErrorCode != "" {
				ts.assertAPIError(respBody, tc.wantErrorCode)
				return
			}

			var resp PurposeResponse
			ts.Require().NoError(json.Unmarshal(respBody, &resp))
			if tc.checkResult != nil {
				tc.checkResult(&resp)
			}
		})
	}
}

// TestGetPurposeVersion covers GET /consent-purposes/{purposeId}/versions/{version}.
func (ts *PurposeAPITestSuite) TestGetPurposeVersion() {
	type testCase struct {
		name          string
		setup         func(orgID string) (purposeID, version string)
		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		checkResult   func(resp *PurposeResponse)
	}

	cases := []testCase{
		{
			name: "get v1 — returns correct version data when v2 also exists",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:        "gv-v1",
					DisplayName: ptr("Version One"),
				}).PurposeID
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{DisplayName: ptr("Version Two")})
				return id, "v1"
			},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeResponse) {
				ts.Equal("v1", resp.Version)
				ts.Require().NotNil(resp.DisplayName)
				ts.Equal("Version One", *resp.DisplayName, "v1 displayName should be 'Version One'")
			},
		},
		{
			name: "get v2 — returns v2 not v1",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "gv-v2")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{DisplayName: ptr("V2 display")})
				return id, "v2"
			},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeResponse) {
				ts.Equal("v2", resp.Version)
				ts.Require().NotNil(resp.DisplayName)
				ts.Equal("V2 display", *resp.DisplayName)
			},
		},
		{
			name: "version not found — 404 CP-4040",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "gv-no-v99")
				return id, "v99"
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "CP-4040",
		},
		{
			name: "invalid version format — 400 CP-4007",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "gv-bad-fmt")
				return id, "2" // must be "v2", not "2"
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4007",
		},
		{
			name: "missing org-id header — 400 CP-4004",
			setup: func(_ string) (string, string) {
				return "00000000-0000-0000-0000-000000000000", "v1"
			},
			omitOrgID:     true,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4004",
		},
	}

	for _, tc := range cases {
		tc := tc
		ts.Run(tc.name, func() {
			orgID := freshOrgID()
			purposeID, version := tc.setup(orgID)

			requestOrgID := orgID
			if tc.omitOrgID {
				requestOrgID = ""
			}

			path := "/api/v1/consent-purposes/" + purposeID + "/versions/" + version
			status, body := ts.doRequest(http.MethodGet, path, requestOrgID, nil)
			ts.Require().Equal(tc.wantStatus, status)

			if tc.wantErrorCode != "" {
				ts.assertAPIError(body, tc.wantErrorCode)
				return
			}

			var resp PurposeResponse
			ts.Require().NoError(json.Unmarshal(body, &resp))
			if tc.checkResult != nil {
				tc.checkResult(&resp)
			}
		})
	}
}

// TestDeletePurposeVersion covers DELETE /consent-purposes/{purposeId}/versions/{version}.
func (ts *PurposeAPITestSuite) TestDeletePurposeVersion() {
	type testCase struct {
		name          string
		setup         func(orgID string) (purposeID, version string)
		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		afterDelete   func(orgID, purposeID string)
	}

	cases := []testCase{
		{
			name: "delete v1 when v2 exists — 204, v2 still accessible",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "dv-two-vers")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{})
				return id, "v1"
			},
			wantStatus: http.StatusNoContent,
			afterDelete: func(orgID, purposeID string) {
				// v1 must be gone
				statusV1, body := ts.doDeletePurposeVersion(orgID, purposeID, "v1")
				ts.Equal(http.StatusNotFound, statusV1, "v1 must not be accessible after deletion")
				ts.assertAPIError(body, "CP-4040")
				// v2 still accessible
				statusV2, v2 := ts.doGetPurposeVersion(orgID, purposeID, "v2")
				ts.Equal(http.StatusOK, statusV2, "v2 must still be accessible")
				ts.Equal("v2", v2.Version)
			},
		},
		{
			name: "delete last version — 204, purpose itself also removed",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "dv-last-ver")
				return id, "v1"
			},
			wantStatus: http.StatusNoContent,
			afterDelete: func(orgID, purposeID string) {
				statusGet, _ := ts.doGetPurpose(orgID, purposeID)
				ts.Equal(http.StatusNotFound, statusGet,
					"purpose must be gone after its last version is deleted")
			},
		},
		{
			name: "non-existent version — 404 CP-4040",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "dv-no-v99")
				return id, "v99"
			},
			wantStatus:    http.StatusNotFound,
			wantErrorCode: "CP-4040",
		},
		{
			name: "invalid version format — 400 CP-4007",
			setup: func(orgID string) (string, string) {
				id := ts.mustCreatePurpose(orgID, "dv-bad-fmt")
				return id, "1" // must be "v1"
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4007",
		},
		{
			name: "missing org-id header — 400 CP-4004",
			setup: func(_ string) (string, string) {
				return "00000000-0000-0000-0000-000000000000", "v1"
			},
			omitOrgID:     true,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4004",
		},
	}

	for _, tc := range cases {
		tc := tc
		ts.Run(tc.name, func() {
			orgID := freshOrgID()
			purposeID, version := tc.setup(orgID)

			requestOrgID := orgID
			if tc.omitOrgID {
				requestOrgID = ""
			}

			status, body := ts.doDeletePurposeVersion(requestOrgID, purposeID, version)
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
