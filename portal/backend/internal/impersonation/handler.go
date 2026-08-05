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
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/wso2/openfgc/portal/backend/internal/proxy"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

const maxRequestBytes = 65536

// Handler serves the /acting/* routes, called by the browser with a verified
// mask token.
type Handler struct {
	svc      *Service
	verifier *MaskVerifier
	gate     *gateClient
	cfg      config.IdentityServerConfig
	authCfg  config.AuthConfig
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewHandler creates an impersonation handler with an initialized service,
// a JWKS-backed mask token verifier, and a client for Nominee Service's gate.
func NewHandler(cfg config.Config) (*Handler, error) {
	svc, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{
		svc:      svc,
		verifier: NewMaskVerifier(cfg.IdentityServer, cfg.Auth),
		gate:     newGateClient(cfg.Internal),
		cfg:      cfg.IdentityServer,
		authCfg:  cfg.Auth,
	}, nil
}

func readBoundedBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() {
		_ = r.Body.Close()
	}()
	limited := io.LimitReader(r.Body, maxRequestBytes+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxRequestBytes {
		return nil, errors.New("request body too large")
	}
	return b, nil
}

func writeISError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotConfigured) {
		writeJSONError(w, http.StatusServiceUnavailable, "IDENTITY_SERVER_NOT_CONFIGURED",
			"identity server impersonation is not configured")
		return
	}
	writeJSONError(w, http.StatusBadGateway, "IDENTITY_SERVER_UNAVAILABLE", "identity server unavailable")
}

func writeProxyError(w http.ResponseWriter, err error) {
	if errors.Is(err, proxy.ErrUpstreamTimeout) {
		writeJSONError(w, http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "upstream timeout")
		return
	}
	if errors.Is(err, proxy.ErrUpstreamResponseTooLarge) {
		writeJSONError(w, http.StatusBadGateway, "UPSTREAM_RESPONSE_TOO_LARGE", "upstream response too large")
		return
	}
	writeJSONError(w, http.StatusBadGateway, "UPSTREAM_UNAVAILABLE", "upstream unavailable")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Code: code, Message: message})
}
