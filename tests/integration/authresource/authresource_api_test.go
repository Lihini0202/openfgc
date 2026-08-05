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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/wso2/openfgc/tests/integration/testutils"
)

var serverURL = testutils.GetTestServerURL()

// orgCounter drives freshOrgID — monotonically increasing within a test run.
var orgCounter atomic.Int64

// freshOrgID returns a unique org ID for each call.
// Using a fresh org per test means tests never share DB state and never need cleanup.
func freshOrgID() string {
	return fmt.Sprintf("test-ar-%d", orgCounter.Add(1))
}

// strPtr converts a string to *string.
func strPtr(s string) *string { return &s }

// =============================================================================
// Suite
// =============================================================================

// AuthResourceAPITestSuite is the testify suite for all authorization resource integration tests.
type AuthResourceAPITestSuite struct {
	suite.Suite
}

func TestAuthResourceAPITestSuite(t *testing.T) {
	suite.Run(t, new(AuthResourceAPITestSuite))
}

func (ts *AuthResourceAPITestSuite) SetupSuite() {
	ts.T().Log("=== AuthResource Integration Test Suite Starting ===")
}

// =============================================================================
// Core HTTP helper
// =============================================================================

// doRequest executes an HTTP request and returns (statusCode, responseBody).
//
//   - orgID: written as the org-id header; pass "" to omit (use for missing-header error cases).
//   - body: nil for GET requests; a struct (JSON-marshalled) or raw string for POST/PUT.
func (ts *AuthResourceAPITestSuite) doRequest(method, path, orgID string, body any) (int, []byte) {
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
// Each typed helper returns (httpStatus, parsedResponse).
// The parsed response is nil when the status code does not match 200 — use
// doRequest directly to access the raw body in error cases.
// =============================================================================

// doCreateAuthResource calls POST /consents/{consentId}/authorizations.
func (ts *AuthResourceAPITestSuite) doCreateAuthResource(
	orgID, consentID string,
	req AuthResourceCreateRequest,
) (int, *AuthResourceResponse) {
	status, body := ts.doRequest(
		http.MethodPost,
		"/api/v1/consents/"+consentID+"/authorizations",
		orgID,
		req,
	)
	if status != http.StatusOK {
		return status, nil
	}
	var resp AuthResourceResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal AuthResourceResponse: %s", body)
	return status, &resp
}

// doListAuthResources calls GET /consents/{consentId}/authorizations.
// Returns (status, list); list is nil on non-200.
func (ts *AuthResourceAPITestSuite) doListAuthResources(
	orgID, consentID string,
) (int, []AuthResourceResponse) {
	status, body := ts.doRequest(
		http.MethodGet,
		"/api/v1/consents/"+consentID+"/authorizations",
		orgID,
		nil,
	)
	if status != http.StatusOK {
		return status, nil
	}
	var resp []AuthResourceResponse
	ts.Require().NoError(json.Unmarshal(body, &resp), "unmarshal []AuthResourceResponse (list): %s", body)
	return status, resp
}

// =============================================================================
// Must-helpers (test setup — use Require so the test stops on failure)
// =============================================================================

// mustCreateConsent creates a minimal consent (type only, no authorizations or purposes)
// and returns its ID. Uses Require so the test fails immediately if setup fails.
func (ts *AuthResourceAPITestSuite) mustCreateConsent(orgID, groupID string) string {
	body := map[string]any{"type": "accounts"}
	rawBody, err := json.Marshal(body)
	ts.Require().NoError(err)

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/consents", bytes.NewReader(rawBody))
	ts.Require().NoError(err)
	req.Header.Set(testutils.HeaderOrgID, orgID)
	req.Header.Set("group-id", groupID)
	req.Header.Set(testutils.HeaderContentType, "application/json")

	resp, err := testutils.GetHTTPClient().Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)
	ts.Require().Equal(http.StatusCreated, resp.StatusCode,
		"mustCreateConsent: unexpected status: %s", respBody)

	var consent struct {
		ID string `json:"id"`
	}
	ts.Require().NoError(json.Unmarshal(respBody, &consent))
	ts.Require().NotEmpty(consent.ID, "mustCreateConsent: consent ID must not be empty")
	return consent.ID
}

// mustCreateAuthResource creates an auth resource and returns it.
// Uses Require so the test fails immediately if setup fails.
func (ts *AuthResourceAPITestSuite) mustCreateAuthResource(
	orgID, consentID string,
	req AuthResourceCreateRequest,
) *AuthResourceResponse {
	status, resp := ts.doCreateAuthResource(orgID, consentID, req)
	ts.Require().Equal(http.StatusOK, status, "mustCreateAuthResource: unexpected HTTP status")
	ts.Require().NotNil(resp)
	return resp
}

// getConsentStatus fetches the current status of a consent.
func (ts *AuthResourceAPITestSuite) getConsentStatus(orgID, consentID string) string {
	status, body := ts.doRequest(http.MethodGet, "/api/v1/consents/"+consentID, orgID, nil)
	ts.Require().Equal(http.StatusOK, status, "getConsentStatus: unexpected status")
	var cs ConsentStatusResponse
	ts.Require().NoError(json.Unmarshal(body, &cs))
	return cs.Status
}

// =============================================================================
// Assertion helpers
// =============================================================================

// assertAPIError parses body as an ErrorResponse, asserts the error code, and
// returns the parsed struct for additional assertions.
func (ts *AuthResourceAPITestSuite) assertAPIError(body []byte, wantCode string) ErrorResponse {
	var errResp ErrorResponse
	ts.Require().NoError(json.Unmarshal(body, &errResp),
		"body is not a valid ErrorResponse: %s", string(body))
	ts.Require().Equal(wantCode, errResp.Code, "unexpected error code; body: %s", string(body))
	ts.Require().NotEmpty(errResp.Message, "error response must have a non-empty message")
	return errResp
}

// assertAuthResourceResponse validates the fields that the API spec mandates are
// always present on an AuthResourceResponse.
func (ts *AuthResourceAPITestSuite) assertAuthResourceResponse(ar *AuthResourceResponse) {
	ts.Require().NotNil(ar)
	ts.Require().NotEmpty(ar.ID, "id must not be empty")
	ts.Require().NotEmpty(ar.Type, "type must not be empty")
	ts.Require().NotEmpty(ar.Status, "status must not be empty")
	// 946684800000 = 2000-01-01 in Unix milliseconds — guards against Unix seconds.
	ts.Require().Greater(ar.UpdatedTime, int64(946684800000), "updatedTime must be a Unix millisecond timestamp")
}
