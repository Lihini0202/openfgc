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

// Package me contains user-facing aggregated /me endpoints for the BFF.
package me

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/wso2/openfgc/portal/backend/internal/proxy"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
	systemcontext "github.com/wso2/openfgc/portal/backend/internal/system/context"
)

// Handler serves /me route groups.
type Handler struct {
	svc *Service
	cfg config.ProxyConfig
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// sessionResponse is what the frontend uses to know whether it's logged in
// and whether to show admin-only navigation.
type sessionResponse struct {
	UserID  string `json:"userId"`
	IsAdmin bool   `json:"isAdmin"`
}

var errRequestBodyTooLarge = errors.New("request body too large")
var consentIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// NewHandler creates a me handler with initialized service.
func NewHandler(cfg config.Config) (*Handler, error) {
	svc, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, cfg: cfg.Proxy}, nil
}

// Session handles GET /me/session, telling the frontend who's logged in and
// whether to show admin-only navigation. Requires only authentication, no
// specific scope - any logged-in user can ask "who am I."
func (h *Handler) Session(w http.ResponseWriter, r *http.Request) {
	principal, ok := systemcontext.PrincipalFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	isAdmin, err := h.svc.IsAdmin(r.Context(), principal.UserID)
	if err != nil {
		slog.Error("me: admin role check failed", "userId", principal.UserID, "error", err)
		writeJSONError(w, http.StatusBadGateway, "IDENTITY_SERVICE_UNAVAILABLE", "identity service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{UserID: principal.UserID, IsAdmin: isAdmin})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Consents handles GET /me/consents.
func (h *Handler) Consents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	userID, ok := h.resolveUserID(w, r)
	if !ok {
		return
	}
	if err := h.svc.Forward(w, r, http.MethodGet, "/api/v1/consents", func(q url.Values) {
		q.Set("userIds", userID)
	}, nil); err != nil {
		writeProxyError(w, err)
	}
}

// ConsentByID handles GET /me/consents/{consentId}.
func (h *Handler) ConsentByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if _, ok := h.resolveUserID(w, r); !ok {
		return
	}
	// TODO: verify the fetched consent belongs to the authenticated user before returning it.
	consentID := r.PathValue("consentId")
	if consentID == "" {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "consent id not found")
		return
	}
	if !isValidConsentID(consentID) {
		writeJSONError(w, http.StatusBadRequest, "INVALID_CONSENT_ID", "invalid consent id")
		return
	}

	baseResp, err := h.svc.ForwardRaw(r, http.MethodGet, "/api/v1/consents/"+url.PathEscape(consentID), nil, nil)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	if baseResp.StatusCode != http.StatusOK {
		h.svc.WriteUpstreamResponse(w, baseResp)
		return
	}

	aggregatedBody, err := h.svc.BuildAggregatedConsentResponse(r, baseResp.Body)
	if err != nil {
		writeProxyError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(aggregatedBody)
}

// ConsentApprove handles POST /me/consents/{consentId}/approve.
func (h *Handler) ConsentApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	userID, ok := h.resolveUserID(w, r)
	if !ok {
		return
	}
	// TODO: verify the fetched consent belongs to the authenticated user before approving it.
	consentID := r.PathValue("consentId")
	if consentID == "" {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "consent id not found")
		return
	}
	if !isValidConsentID(consentID) {
		writeJSONError(w, http.StatusBadRequest, "INVALID_CONSENT_ID", "invalid consent id")
		return
	}
	body, err := h.readBoundedBody(r)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}
	selections, err := parseApprovalSelections(body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid request payload")
		return
	}
	baseResp, err := h.svc.ForwardRaw(r, http.MethodGet, "/api/v1/consents/"+url.PathEscape(consentID), nil, nil)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	if baseResp.StatusCode != http.StatusOK {
		h.svc.WriteUpstreamResponse(w, baseResp)
		return
	}

	payload, trustedClientID, err := h.svc.BuildApprovalUpdatePayload(r, baseResp.Body, selections, userID)
	if err != nil {
		if errors.Is(err, proxy.ErrUpstreamTimeout) || errors.Is(err, proxy.ErrUpstreamUnavailable) || errors.Is(err, proxy.ErrUpstreamResponseTooLarge) {
			writeProxyError(w, err)
			return
		}
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid request payload")
		return
	}
	if err := h.svc.ForwardWithClientID(w, r, http.MethodPut, "/api/v1/consents/"+url.PathEscape(consentID), nil, payload, trustedClientID); err != nil {
		writeProxyError(w, err)
	}
}

// ConsentRevoke handles PUT /me/consents/{consentId}/revoke.
func (h *Handler) ConsentRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	userID, ok := h.resolveUserID(w, r)
	if !ok {
		return
	}
	// TODO: verify the targeted consent belongs to the authenticated user before revoking it.
	consentID := r.PathValue("consentId")
	if consentID == "" {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "consent id not found")
		return
	}
	if !isValidConsentID(consentID) {
		writeJSONError(w, http.StatusBadRequest, "INVALID_CONSENT_ID", "invalid consent id")
		return
	}
	body, err := h.readBoundedBody(r)
	if err != nil {
		writeBodyReadError(w, err)
		return
	}
	payload, err := buildRevokePayload(body, userID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid request payload")
		return
	}
	if err := h.svc.Forward(w, r, http.MethodPut, "/api/v1/consents/"+url.PathEscape(consentID)+"/revoke", nil, payload); err != nil {
		writeProxyError(w, err)
	}
}

func isValidConsentID(id string) bool {
	return consentIDPattern.MatchString(strings.TrimSpace(id))
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

func (h *Handler) resolveUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal, ok := systemcontext.PrincipalFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return "", false
	}
	return principal.UserID, true
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
