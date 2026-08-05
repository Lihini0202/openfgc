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

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMeEndpointsRejectInvalidConsentID(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	bff := newPhase2Server(t, upstream.URL)
	defer bff.Close()

	testCases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "get by id", method: http.MethodGet, path: "/me/consents/not-a-uuid"},
		{name: "approve", method: http.MethodPost, path: "/me/consents/not-a-uuid/approve", body: "[]"},
		{name: "revoke", method: http.MethodPut, path: "/me/consents/not-a-uuid/revoke", body: "{}"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamCalled = false

			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}

			req, err := http.NewRequest(tc.method, bff.URL+tc.path, body)
			if err != nil {
				t.Fatalf("request creation failed: %v", err)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", resp.StatusCode)
			}
			if upstreamCalled {
				t.Fatal("expected request to be rejected before upstream call")
			}

			var payload map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				t.Fatalf("expected json error payload: %v", err)
			}
			if payload["code"] != "INVALID_CONSENT_ID" {
				t.Fatalf("expected INVALID_CONSENT_ID, got %v", payload["code"])
			}
		})
	}
}
