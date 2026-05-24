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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/wso2/openfgc/tests/integration/testutils"
)

var serverURL = testutils.GetTestServerURL()

// orgCounter drives freshOrgID — a monotonically increasing counter.
// No UUID library needed; the value is unique within a test run.
var orgCounter atomic.Int64

// freshOrgID returns a unique org ID for each call.
// Tests use this instead of a shared constant so they never share DB state
// and never need per-test cleanup.
func freshOrgID() string {
	return fmt.Sprintf("test-cp-%d", orgCounter.Add(1))
}

// ptr converts a string literal to *string, used when building request bodies.
func ptr(s string) *string { return &s }

// =============================================================================
// Suite
// =============================================================================

// PurposeAPITestSuite is the testify suite for all consent purpose integration tests.
type PurposeAPITestSuite struct {
	suite.Suite
}

func TestPurposeAPITestSuite(t *testing.T) {
	suite.Run(t, new(PurposeAPITestSuite))
}

func (ts *PurposeAPITestSuite) SetupSuite() {
	ts.T().Log("=== ConsentPurpose Integration Test Suite Starting ===")
}

// =============================================================================
// Core HTTP helper
// =============================================================================

// doRequest executes an HTTP request and returns (statusCode, responseBody).
//
//   - orgID: written as the org-id header; pass "" to omit it entirely
//     (use this for missing-header error-case tests).
//   - body: nil for GET/DELETE; a struct (JSON-marshalled) or a raw string for POST.
func (ts *PurposeAPITestSuite) doRequest(method, path, orgID string, body any) (int, []byte) {
	var rawBody []byte
	if body != nil { //nolint:nestif
		if s, ok := body.(string); ok {
			rawBody = []byte(s)
		} else {
			var err error
			rawBody, err = json.Marshal(body)
			ts.Require().NoError(err, "marshal request body")
		}
	}

	req, err := http.NewRequest(method, serverURL+path, bytes.NewReader(rawBody))
	ts.Require().NoError(err)

	if orgID != "" {
		req.Header.Set(testutils.HeaderOrgID, orgID)
	}
	if len(rawBody) > 0 {
		req.Header.Set(testutils.HeaderContentType, "application/json")
	}

	resp, err := testutils.GetHTTPClient().Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)
	return resp.StatusCode, respBody
}

// =============================================================================
// Typed endpoint helpers
//
// Each helper returns (httpStatus, parsedResponse).
// The parsed response is nil when the status code does not match the expected
// success code — use doRequest directly to access the raw body in those cases.
// =============================================================================

// doCreatePurpose handles POST /consent-purposes.
// Pass groupID="" to omit the group-id header — the server will treat it as an
// org-level purpose and set groupId = orgId automatically.
func (ts *PurposeAPITestSuite) doCreatePurpose(orgID, groupID string, req CreatePurposeRequest) (int, *PurposeResponse) {
	rawBody, err := json.Marshal(req)
	ts.Require().NoError(err)

	httpReq, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/consent-purposes", bytes.NewReader(rawBody))
	ts.Require().NoError(err)
	if orgID != "" {
		httpReq.Header.Set(testutils.HeaderOrgID, orgID)
	}
	if groupID != "" {
		httpReq.Header.Set("group-id", groupID)
	}
	httpReq.Header.Set(testutils.HeaderContentType, "application/json")

	resp, err := testutils.GetHTTPClient().Do(httpReq)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)

	if resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, nil
	}
	var purpose PurposeResponse
	ts.Require().NoError(json.Unmarshal(body, &purpose), "unmarshal PurposeResponse: %s", body)
	return resp.StatusCode, &purpose
}

// doCreatePurposeFull sends any body (struct or raw string) to POST /consent-purposes,
// setting both org-id and the optional group-id header, and always returns the raw response.
// Use this in table-driven tests that need to inspect the body for both success and error cases.
func (ts *PurposeAPITestSuite) doCreatePurposeFull(orgID, groupID string, body any) (int, []byte) {
	var rawBody []byte
	if s, ok := body.(string); ok {
		rawBody = []byte(s)
	} else {
		var err error
		rawBody, err = json.Marshal(body)
		ts.Require().NoError(err, "marshal request body")
	}

	httpReq, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/consent-purposes", bytes.NewReader(rawBody))
	ts.Require().NoError(err)
	if orgID != "" {
		httpReq.Header.Set(testutils.HeaderOrgID, orgID)
	}
	if groupID != "" {
		httpReq.Header.Set("group-id", groupID)
	}
	if len(rawBody) > 0 {
		httpReq.Header.Set(testutils.HeaderContentType, "application/json")
	}

	resp, err := testutils.GetHTTPClient().Do(httpReq)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)
	return resp.StatusCode, respBody
}

func (ts *PurposeAPITestSuite) doGetPurpose(orgID, purposeID string) (int, *PurposeResponse) {
	status, body := ts.doRequest(http.MethodGet, "/api/v1/consent-purposes/"+purposeID, orgID, nil)
	if status != http.StatusOK {
		return status, nil
	}
	var resp PurposeResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal PurposeResponse")
	return status, &resp
}

func (ts *PurposeAPITestSuite) doListPurposes(orgID string, params url.Values) (int, *PurposeListResponse) {
	path := "/api/v1/consent-purposes"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	status, body := ts.doRequest(http.MethodGet, path, orgID, nil)
	if status != http.StatusOK {
		return status, nil
	}
	var resp PurposeListResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal PurposeListResponse")
	return status, &resp
}

func (ts *PurposeAPITestSuite) doGetPurposeVersions(orgID, purposeID string) (int, *PurposeVersionListResponse) {
	path := fmt.Sprintf("/api/v1/consent-purposes/%s/versions", purposeID)
	status, body := ts.doRequest(http.MethodGet, path, orgID, nil)
	if status != http.StatusOK {
		return status, nil
	}
	var resp PurposeVersionListResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal PurposeVersionListResponse")
	return status, &resp
}

func (ts *PurposeAPITestSuite) doCreatePurposeVersion(orgID, purposeID string, req CreatePurposeVersionRequest) (int, *PurposeResponse) {
	path := fmt.Sprintf("/api/v1/consent-purposes/%s/versions", purposeID)
	status, body := ts.doRequest(http.MethodPost, path, orgID, req)
	if status != http.StatusCreated {
		return status, nil
	}
	var resp PurposeResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal PurposeResponse (createPurposeVersion): %s", body)
	return status, &resp
}

func (ts *PurposeAPITestSuite) doGetPurposeVersion(orgID, purposeID, version string) (int, *PurposeResponse) {
	path := fmt.Sprintf("/api/v1/consent-purposes/%s/versions/%s", purposeID, version)
	status, body := ts.doRequest(http.MethodGet, path, orgID, nil)
	if status != http.StatusOK {
		return status, nil
	}
	var resp PurposeResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal PurposeResponse (getPurposeVersion)")
	return status, &resp
}

func (ts *PurposeAPITestSuite) doDeletePurposeVersion(orgID, purposeID, version string) (int, []byte) {
	path := fmt.Sprintf("/api/v1/consent-purposes/%s/versions/%s", purposeID, version)
	return ts.doRequest(http.MethodDelete, path, orgID, nil)
}

func (ts *PurposeAPITestSuite) doDeletePurpose(orgID, purposeID string) (int, []byte) {
	return ts.doRequest(http.MethodDelete, "/api/v1/consent-purposes/"+purposeID, orgID, nil)
}

// =============================================================================
// Must-helpers
//
// These are for test setup steps, not the operation under test.
// They call Require internally so the test stops immediately if setup fails,
// keeping failure messages focused on the actual assertion being tested.
// =============================================================================

// autoElemCounter generates unique names for auto-created elements inside must-helpers.
var autoElemCounter atomic.Int64

// nextAutoElem creates a uniquely-named "basic" element in orgID and returns a ready-to-use
// ElementRefRequest. Call this when you need an element but don't care about its name.
func (ts *PurposeAPITestSuite) nextAutoElem(orgID string) ElementRefRequest {
	name := fmt.Sprintf("ae-%d", autoElemCounter.Add(1))
	ts.mustCreateElement(orgID, name, "basic")
	return ElementRefRequest{Name: name}
}

// mustCreatePurpose creates an org-level purpose with one auto-generated element and returns its purposeId.
func (ts *PurposeAPITestSuite) mustCreatePurpose(orgID, name string) string {
	return ts.mustCreatePurposeWith(orgID, "", CreatePurposeRequest{Name: name}).PurposeID
}

// mustCreatePurposeWith creates a purpose from a full request and returns the response.
// If req.Elements is empty it auto-creates one element so the server's validation passes.
func (ts *PurposeAPITestSuite) mustCreatePurposeWith(orgID, groupID string, req CreatePurposeRequest) *PurposeResponse {
	if len(req.Elements) == 0 {
		req.Elements = []ElementRefRequest{ts.nextAutoElem(orgID)}
	}
	status, resp := ts.doCreatePurpose(orgID, groupID, req)
	ts.Require().Equal(http.StatusCreated, status, "mustCreatePurposeWith: unexpected HTTP status")
	ts.Require().NotNil(resp)
	return resp
}

// mustCreatePurposeVersion creates a new version on an existing purpose and returns the response.
// If req.Elements is empty it auto-creates one element so the server's validation passes.
func (ts *PurposeAPITestSuite) mustCreatePurposeVersion(orgID, purposeID string, req CreatePurposeVersionRequest) *PurposeResponse {
	if len(req.Elements) == 0 {
		req.Elements = []ElementRefRequest{ts.nextAutoElem(orgID)}
	}
	status, resp := ts.doCreatePurposeVersion(orgID, purposeID, req)
	ts.Require().Equal(http.StatusCreated, status, "mustCreatePurposeVersion: unexpected HTTP status")
	ts.Require().NotNil(resp)
	return resp
}

// mustCreateElement creates a single consent element via the /consent-elements API and returns its elementId.
// Used in purpose tests that need real element links.
func (ts *PurposeAPITestSuite) mustCreateElement(orgID, name, elemType string) string {
	body := []map[string]any{{"name": name, "type": elemType}}
	status, respBody := ts.doRequest(http.MethodPost, "/api/v1/consent-elements", orgID, body)
	ts.Require().Equal(http.StatusOK, status, "mustCreateElement: unexpected status for element '%s'", name)

	var batchResp struct {
		Results []struct {
			Status  string `json:"status"`
			Element *struct {
				ElementID string `json:"elementId"`
			} `json:"element"`
			Error *string `json:"error"`
		} `json:"results"`
	}
	ts.Require().NoError(json.Unmarshal(respBody, &batchResp), "mustCreateElement: parse batch response")
	ts.Require().Len(batchResp.Results, 1)
	ts.Require().Equal("SUCCESS", batchResp.Results[0].Status,
		"mustCreateElement: FAILED — error: %v", batchResp.Results[0].Error)
	ts.Require().NotNil(batchResp.Results[0].Element)
	return batchResp.Results[0].Element.ElementID
}

// mustCreateElementWith creates an element with custom fields (e.g. namespace) and returns its elementId.
// fields must include at least "name" and "type".
func (ts *PurposeAPITestSuite) mustCreateElementWith(orgID string, fields map[string]any) string {
	body := []map[string]any{fields}
	status, respBody := ts.doRequest(http.MethodPost, "/api/v1/consent-elements", orgID, body)
	ts.Require().Equal(http.StatusOK, status, "mustCreateElementWith: unexpected status")

	var batchResp struct {
		Results []struct {
			Status  string `json:"status"`
			Element *struct {
				ElementID string `json:"elementId"`
			} `json:"element"`
			Error *string `json:"error"`
		} `json:"results"`
	}
	ts.Require().NoError(json.Unmarshal(respBody, &batchResp), "mustCreateElementWith: parse batch response")
	ts.Require().Len(batchResp.Results, 1)
	ts.Require().Equal("SUCCESS", batchResp.Results[0].Status,
		"mustCreateElementWith: FAILED — error: %v", batchResp.Results[0].Error)
	ts.Require().NotNil(batchResp.Results[0].Element)
	return batchResp.Results[0].Element.ElementID
}

// =============================================================================
// Assertion helpers
// =============================================================================

// assertAPIError parses body as an ErrorResponse, asserts the error code, and
// returns the parsed struct so callers can make additional assertions.
func (ts *PurposeAPITestSuite) assertAPIError(body []byte, wantCode string) ErrorResponse {
	var errResp ErrorResponse
	ts.Require().NoError(json.Unmarshal(body, &errResp),
		"body is not a valid ErrorResponse: %s", string(body))
	ts.Require().Equal(wantCode, errResp.Code, "unexpected error code; body: %s", string(body))
	ts.Require().NotEmpty(errResp.Message, "error response must have a non-empty message")
	return errResp
}

// assertPurposeResponse validates the fields that the swagger spec mandates are
// always present on a PurposeResponse, regardless of which endpoint returned it.
func (ts *PurposeAPITestSuite) assertPurposeResponse(p *PurposeResponse, wantName string) {
	ts.Require().NotNil(p)
	ts.Require().NotEmpty(p.PurposeID, "purposeId must not be empty")
	ts.Require().NotEmpty(p.GroupID, "groupId must not be empty")
	ts.Require().NotEmpty(p.Version, "version must not be empty (expected 'v1', 'v2', …)")
	// 946684800000 = 2000-01-01 in Unix milliseconds — ensures millis, not seconds.
	ts.Require().Greater(p.CreatedTime, int64(946684800000), "createdTime must be a Unix millisecond timestamp")
	ts.Equal(wantName, p.Name, "name mismatch")
}

// assertPurposeElement validates every field on a PurposeElementResponse.
// wantNamespace should be "default" for elements created without an explicit namespace.
func (ts *PurposeAPITestSuite) assertPurposeElement(
	elem PurposeElementResponse,
	wantName, wantNamespace, wantVersion string,
	wantMandatory bool,
) {
	ts.NotEmpty(elem.ElementID, "elementId must not be empty")
	ts.Equal(wantName, elem.Name, "element name mismatch")
	ts.Equal(wantNamespace, elem.Namespace, "element namespace mismatch")
	ts.Equal(wantVersion, elem.Version, "element version mismatch")
	ts.Equal(wantMandatory, elem.Mandatory, "element mandatory mismatch")
}
