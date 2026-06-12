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
	"net/url"
)

// TestListPurposes covers GET /consent-purposes with all filter and pagination combinations.
func (ts *PurposeAPITestSuite) TestListPurposes() {
	type testCase struct {
		name          string
		setup         func(orgID string)
		params        url.Values
		omitOrgID     bool
		wantStatus    int
		wantErrorCode string
		checkResult   func(resp *PurposeListResponse)
	}

	cases := []testCase{
		// -----------------------------------------------------------------------
		// Baseline responses
		// -----------------------------------------------------------------------
		{
			name:       "empty org — returns empty data with correct metadata",
			setup:      func(_ string) {},
			params:     nil,
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Empty(resp.Data, "no purposes should exist for a fresh org")
				ts.Equal(0, resp.Metadata.Total)
				ts.Equal(0, resp.Metadata.Count)
			},
		},
		{
			name: "multiple purposes — metadata reflects correct counts",
			setup: func(orgID string) {
				ts.mustCreatePurpose(orgID, "list-p-a")
				ts.mustCreatePurpose(orgID, "list-p-b")
				ts.mustCreatePurpose(orgID, "list-p-c")
			},
			params:     nil,
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Equal(3, resp.Metadata.Total)
				ts.Equal(3, resp.Metadata.Count)
				ts.Len(resp.Data, 3)
			},
		},

		// -----------------------------------------------------------------------
		// Filter: purposeName (LIKE / substring match: %name%)
		// -----------------------------------------------------------------------
		{
			name: "purposeName filter — returns only substring-matching purposes",
			setup: func(orgID string) {
				// Use names without substring overlap so the LIKE filter is deterministic.
				ts.mustCreatePurpose(orgID, "pnf-consent")   // target: contains "pnf-consent"
				ts.mustCreatePurpose(orgID, "pnf-analytics") // no match
				ts.mustCreatePurpose(orgID, "pnf-audit")     // no match
			},
			params:     url.Values{"purposeName": {"pnf-consent"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total, "purposeName LIKE filter must match exactly one purpose")
				ts.Equal("pnf-consent", resp.Data[0].Name)
			},
		},

		// -----------------------------------------------------------------------
		// Filter: groupIds
		// -----------------------------------------------------------------------
		{
			name: "groupIds filter — returns only purposes in specified groups",
			setup: func(orgID string) {
				ts.mustCreatePurposeWith(orgID, "grp-x", CreatePurposeRequest{Name: "lp-grp-x"})
				ts.mustCreatePurposeWith(orgID, "grp-y", CreatePurposeRequest{Name: "lp-grp-y"})
				ts.mustCreatePurpose(orgID, "lp-org-level") // groupId = orgId
			},
			params:     url.Values{"groupIds": {"grp-x,grp-y"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Equal(2, resp.Metadata.Total, "should only return purposes from grp-x and grp-y")
				names := make([]string, len(resp.Data))
				for i, p := range resp.Data {
					names[i] = p.Name
				}
				ts.Contains(names, "lp-grp-x")
				ts.Contains(names, "lp-grp-y")
			},
		},

		// -----------------------------------------------------------------------
		// Filter: elementName / elementNamespace
		// -----------------------------------------------------------------------
		{
			name: "elementName filter — returns only purposes containing that element",
			setup: func(orgID string) {
				ts.mustCreateElement(orgID, "lp-email", "basic")
				ts.mustCreateElement(orgID, "lp-phone", "basic")
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-has-email",
					Elements: []ElementRefRequest{{Name: "lp-email"}},
				})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-has-phone",
					Elements: []ElementRefRequest{{Name: "lp-phone"}},
				})
				ts.mustCreatePurpose(orgID, "lp-no-elems")
			},
			params:     url.Values{"elementName": {"lp-email"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total, "only 1 purpose has lp-email")
				ts.Equal("lp-has-email", resp.Data[0].Name)
			},
		},
		{
			name: "elementNamespace filter — returns only purposes with elements in that namespace",
			setup: func(orgID string) {
				// Create element with explicit namespace
				ts.doRequest(http.MethodPost, "/api/v1/consent-elements", orgID,
					[]map[string]any{{"name": "lp-ns-elem", "type": "basic", "namespace": "payroll"}})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-payroll-purpose",
					Elements: []ElementRefRequest{{Name: "lp-ns-elem", Namespace: "payroll"}},
				})
				ts.mustCreatePurpose(orgID, "lp-unrelated")
			},
			params:     url.Values{"elementNamespace": {"payroll"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total)
				ts.Equal("lp-payroll-purpose", resp.Data[0].Name)
			},
		},

		// -----------------------------------------------------------------------
		// Filter: elementName + elementNamespace combined
		// -----------------------------------------------------------------------
		{
			name: "elementName + elementNamespace — returns only purposes with that exact name+namespace combo",
			setup: func(orgID string) {
				ts.mustCreateElement(orgID, "lp-comb-elem", "basic") // default namespace
				ts.mustCreateElementWith(orgID, map[string]any{"name": "lp-comb-elem", "type": "basic", "namespace": "finance"})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-comb-default",
					Elements: []ElementRefRequest{{Name: "lp-comb-elem"}},
				})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-comb-finance",
					Elements: []ElementRefRequest{{Name: "lp-comb-elem", Namespace: "finance"}},
				})
			},
			params:     url.Values{"elementName": {"lp-comb-elem"}, "elementNamespace": {"finance"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total, "combined name+namespace filter must match exactly one purpose")
				ts.Equal("lp-comb-finance", resp.Data[0].Name)
			},
		},

		// -----------------------------------------------------------------------
		// Filter: purposeVersion (requires purposeName)
		// -----------------------------------------------------------------------
		{
			name: "purposeVersion + purposeName — returns specified version",
			setup: func(orgID string) {
				id := ts.mustCreatePurpose(orgID, "lp-versioned")
				ts.mustCreatePurposeVersion(orgID, id, CreatePurposeVersionRequest{
					DisplayName: ptr("Version Two"),
				})
			},
			params:     url.Values{"purposeName": {"lp-versioned"}, "purposeVersion": {"v2"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total)
				ts.Equal("v2", resp.Data[0].Version)
				ts.Require().NotNil(resp.Data[0].DisplayName)
				ts.Equal("Version Two", *resp.Data[0].DisplayName)
			},
		},
		{
			name:          "purposeVersion without purposeName — 400 CP-4008",
			setup:         func(_ string) {},
			params:        url.Values{"purposeVersion": {"v1"}},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4008",
		},

		// -----------------------------------------------------------------------
		// Filter: elementVersion (requires elementName or elementNamespace)
		// -----------------------------------------------------------------------
		{
			name:          "elementVersion without elementName or elementNamespace — 400 CP-4008",
			setup:         func(_ string) {},
			params:        url.Values{"elementVersion": {"v1"}},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4008",
		},
		{
			name: "elementVersion + elementName — returns only purposes using that element at that version",
			setup: func(orgID string) {
				elemID := ts.mustCreateElement(orgID, "lp-ev-elem", "basic")
				// Create v2 so latest = v2; the other purpose will pin to v1.
				ts.doRequest(http.MethodPost, "/api/v1/consent-elements/"+elemID+"/versions", orgID, map[string]string{})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-ev-v1-purpose",
					Elements: []ElementRefRequest{{Name: "lp-ev-elem", Version: ptr("v1")}},
				})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-ev-latest-purpose",
					Elements: []ElementRefRequest{{Name: "lp-ev-elem"}}, // resolves to v2
				})
			},
			params:     url.Values{"elementName": {"lp-ev-elem"}, "elementVersion": {"v1"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total, "only the v1-pinned purpose should match")
				ts.Equal("lp-ev-v1-purpose", resp.Data[0].Name)
			},
		},
		{
			name: "elementVersion + elementNamespace — returns only purposes with namespace element at that version",
			setup: func(orgID string) {
				elemID := ts.mustCreateElementWith(orgID, map[string]any{"name": "lp-ev-ns-elem", "type": "basic", "namespace": "billing"})
				ts.doRequest(http.MethodPost, "/api/v1/consent-elements/"+elemID+"/versions", orgID, map[string]string{})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-ev-ns-v1-purpose",
					Elements: []ElementRefRequest{{Name: "lp-ev-ns-elem", Namespace: "billing", Version: ptr("v1")}},
				})
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:     "lp-ev-ns-latest-purpose",
					Elements: []ElementRefRequest{{Name: "lp-ev-ns-elem", Namespace: "billing"}}, // resolves to v2
				})
			},
			params:     url.Values{"elementNamespace": {"billing"}, "elementVersion": {"v1"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Equal(1, resp.Metadata.Total, "only the v1-pinned purpose should match")
				ts.Equal("lp-ev-ns-v1-purpose", resp.Data[0].Name)
			},
		},

		// -----------------------------------------------------------------------
		// details=true — elements included in each purpose
		// -----------------------------------------------------------------------
		{
			name: "details=false (default) — elements and properties not included in list response",
			setup: func(orgID string) {
				ts.mustCreateElement(orgID, "lp-detail-elem", "basic")
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:       "lp-no-detail",
					Properties: map[string]string{"tier": "gold"},
					Elements:   []ElementRefRequest{{Name: "lp-detail-elem"}},
				})
			},
			params:     nil,
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Len(resp.Data, 1)
				ts.Empty(resp.Data[0].Elements, "elements must be omitted when details=false")
				ts.Empty(resp.Data[0].Properties, "properties must be omitted when details=false")
			},
		},
		{
			name: "details=true — elements and properties included in list response",
			setup: func(orgID string) {
				ts.mustCreateElement(orgID, "lp-detail-elem2", "basic")
				ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{
					Name:       "lp-with-detail",
					Properties: map[string]string{"env": "staging"},
					Elements:   []ElementRefRequest{{Name: "lp-detail-elem2", Mandatory: true}},
				})
			},
			params:     url.Values{"details": {"true"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Require().Len(resp.Data, 1)
				ts.Require().Len(resp.Data[0].Elements, 1, "elements must be included when details=true")
				ts.assertPurposeElement(resp.Data[0].Elements[0], "lp-detail-elem2", "default", "v1", true)
				ts.Require().NotEmpty(resp.Data[0].Properties, "properties must be included when details=true")
				ts.Equal("staging", resp.Data[0].Properties["env"])
			},
		},

		// -----------------------------------------------------------------------
		// Pagination
		// -----------------------------------------------------------------------
		{
			name: "pagination — limit=1 returns only one result",
			setup: func(orgID string) {
				ts.mustCreatePurpose(orgID, "pg-first")
				ts.mustCreatePurpose(orgID, "pg-second")
				ts.mustCreatePurpose(orgID, "pg-third")
			},
			params:     url.Values{"limit": {"1"}, "offset": {"0"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Equal(3, resp.Metadata.Total, "total must reflect all purposes")
				ts.Equal(1, resp.Metadata.Count, "count must reflect items returned in this page")
				ts.Equal(1, resp.Metadata.Limit)
				ts.Equal(0, resp.Metadata.Offset)
				ts.Len(resp.Data, 1)
			},
		},
		{
			name: "pagination — offset=1 skips the first result",
			setup: func(orgID string) {
				ts.mustCreatePurpose(orgID, "pg-off-a")
				ts.mustCreatePurpose(orgID, "pg-off-b")
			},
			params:     url.Values{"limit": {"1"}, "offset": {"1"}},
			wantStatus: http.StatusOK,
			checkResult: func(resp *PurposeListResponse) {
				ts.Equal(2, resp.Metadata.Total)
				ts.Equal(1, resp.Metadata.Count)
				ts.Equal(1, resp.Metadata.Offset)
				ts.Len(resp.Data, 1)
			},
		},

		// -----------------------------------------------------------------------
		// Missing org-id
		// -----------------------------------------------------------------------
		{
			name:          "missing org-id header — 400 CP-4004",
			omitOrgID:     true,
			setup:         func(_ string) {},
			params:        nil,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "CP-4004",
		},
	}

	for _, tc := range cases {
		tc := tc
		ts.Run(tc.name, func() {
			orgID := freshOrgID()

			if tc.setup != nil {
				tc.setup(orgID)
			}

			requestOrgID := orgID
			if tc.omitOrgID {
				requestOrgID = ""
			}

			path := "/api/v1/consent-purposes"
			if len(tc.params) > 0 {
				path += "?" + tc.params.Encode()
			}
			status, body := ts.doRequest(http.MethodGet, path, requestOrgID, nil)
			ts.Require().Equal(tc.wantStatus, status)

			if tc.wantErrorCode != "" {
				ts.assertAPIError(body, tc.wantErrorCode)
				return
			}

			status2, resp := ts.doListPurposes(orgID, tc.params)
			ts.Require().Equal(http.StatusOK, status2)
			if tc.checkResult != nil {
				tc.checkResult(resp)
			}
		})
	}
}
