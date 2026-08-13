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

package impersonation

import (
	"net/http"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Initialize sets up the impersonation module and registers the acting routes.
func Initialize(mux *http.ServeMux, cfg config.Config) error {
	handler, err := NewHandler(cfg)
	if err != nil {
		return err
	}

	// Acting session lifecycle. StartActing is a top-level browser navigation,
	// not an XHR: IS identifies the impersonator from its own session cookie,
	// and returns the subject_token in a fragment only the browser can read.
	mux.Handle("GET /acting/start", http.HandlerFunc(handler.StartActing))
	mux.Handle("POST /acting/exchange", http.HandlerFunc(handler.ExchangeActing))
	mux.Handle("POST /acting/stop", http.HandlerFunc(handler.StopActing))

	// Mask-token routes: the nominee calls these with a verified impersonation
	// token (sub=owner, act.sub=nominee). Each request re-checks both the
	// token's scope ceiling and the live nomination gate.
	mux.Handle("GET /acting/consents", http.HandlerFunc(handler.ActingListConsents))
	mux.Handle("GET /acting/consents/{consentId}", http.HandlerFunc(handler.ActingGetConsent))
	mux.Handle("POST /acting/consents/{consentId}/revoke", http.HandlerFunc(handler.ActingRevokeConsent))
	mux.Handle("POST /acting/consents/{consentId}/approve", http.HandlerFunc(handler.ActingApproveConsent))

	return nil
}
