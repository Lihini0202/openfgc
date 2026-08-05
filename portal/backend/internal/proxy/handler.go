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

package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Handler serves passthrough /api routes.
type Handler struct {
	svc *Service
	cfg config.ProxyConfig
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

var errRequestBodyTooLarge = errors.New("request body too large")

// NewHandler creates a proxy handler with initialized service.
func NewHandler(cfg config.ProxyConfig) (*Handler, error) {
	svc, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, cfg: cfg}, nil
}

// API proxies passthrough /api/* routes to /api/v1/* after allowlist checks.
func (h *Handler) API(w http.ResponseWriter, r *http.Request) {
	knownPath, methodAllowed := h.svc.CheckAPIAccess(r.Method, r.URL.Path)
	if !knownPath {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "route not found")
		return
	}
	if !h.svc.IsAllowedPassthroughMethod(r.Method) || !methodAllowed {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/api")
	if !ok {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "route not found")
		return
	}
	if path == "" {
		path = "/"
	}
	body, err := h.readBoundedBody(r)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}
	if err := h.svc.Forward(w, r, r.Method, "/api/v1"+path, nil, body); err != nil {
		writeProxyError(w, err)
	}
}

func writeProxyError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUpstreamTimeout) {
		writeJSONError(w, http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "upstream timeout")
		return
	}
	if errors.Is(err, ErrUpstreamResponseTooLarge) {
		writeJSONError(w, http.StatusBadGateway, "UPSTREAM_RESPONSE_TOO_LARGE", "upstream response too large")
		return
	}
	writeJSONError(w, http.StatusBadGateway, "UPSTREAM_UNAVAILABLE", "upstream unavailable")
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Code: code, Message: message})
}

func writeBodyReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestBodyTooLarge) {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request entity too large")
		return
	}
	writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "invalid request body")
}

func (h *Handler) readBoundedBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() {
		_ = r.Body.Close()
	}()
	limited := io.LimitReader(r.Body, h.cfg.MaxRequestBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > h.cfg.MaxRequestBytes {
		return nil, errRequestBodyTooLarge
	}
	return body, nil
}
