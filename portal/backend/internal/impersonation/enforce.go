/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

package impersonation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/me"
	"github.com/wso2/openfgc/portal/backend/internal/system/auth"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
	systemcontext "github.com/wso2/openfgc/portal/backend/internal/system/context"
)

// Permission strings as returned by Nominee Service.
const (
	permConsentView    = "CONSENT_VIEW"
	permConsentRevoke  = "CONSENT_REVOKE"
	permConsentApprove = "CONSENT_APPROVE"
)

// actingPolicy binds one acting operation to the two independent things that
// must both hold before it proceeds:
//
//	scope      - what IS minted into the token. Narrowed at mint time to what the
//	             owner granted, so it is a *ceiling* fixed at session start.
//	permission - what Nominee Service says the owner grants right now. Re-read on
//	             every request, so it is the *live* value.
//
// Both are required. The scope alone would go stale the moment an owner edits a
// grant or an administrator deactivates; the live check alone would leave an
// over-privileged token in circulation.
type actingPolicy struct {
	scope      string
	permission string
}

var (
	policyListConsents   = actingPolicy{scope: auth.ScopeConsentsReadSelf, permission: permConsentView}
	policyRevokeConsent  = actingPolicy{scope: auth.ScopeConsentsWriteSelf, permission: permConsentRevoke}
	policyApproveConsent = actingPolicy{scope: auth.ScopeConsentsApproveSelf, permission: permConsentApprove}
)

// gateClient calls Nominee Service's nomination gate. All configuration is
// explicit: there are no environment fallbacks and no default key, so a missing
// value fails at startup rather than silently producing a working secret.
type gateClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newGateClient(cfg config.InternalConfig) *gateClient {
	timeout := cfg.GateTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &gateClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.NomineeServiceURL), "/"),
		apiKey:  strings.TrimSpace(cfg.GateAPIKey),
		http:    &http.Client{Timeout: timeout},
	}
}

// ErrGateUnavailable means the nomination gate could not be consulted. It is
// never treated as permission to proceed.
var ErrGateUnavailable = errors.New("impersonation: nomination gate unavailable")

type gateDecision struct {
	Active      bool     `json:"active"`
	Permissions []string `json:"permissions"`
}

func (g *gateClient) permissions(ctx context.Context, owner, nominee string) (gateDecision, error) {
	if g.baseURL == "" || g.apiKey == "" {
		return gateDecision{}, fmt.Errorf("%w: gate is not configured", ErrGateUnavailable)
	}

	endpoint := fmt.Sprintf("%s/internal/nominations/permissions?owner=%s&nominee=%s",
		g.baseURL, url.QueryEscape(owner), url.QueryEscape(nominee))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return gateDecision{}, fmt.Errorf("%w: %w", ErrGateUnavailable, err)
	}
	req.Header.Set("X-Internal-Key", g.apiKey)

	resp, err := g.http.Do(req)
	if err != nil {
		return gateDecision{}, fmt.Errorf("%w: %w", ErrGateUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return gateDecision{}, fmt.Errorf("%w: gate returned HTTP %d", ErrGateUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return gateDecision{}, fmt.Errorf("%w: %w", ErrGateUnavailable, err)
	}
	var decision gateDecision
	if err := json.Unmarshal(body, &decision); err != nil {
		return gateDecision{}, fmt.Errorf("%w: invalid gate response: %w", ErrGateUnavailable, err)
	}
	return decision, nil
}

func hasPermission(list []string, want string) bool {
	return slices.Contains(list, want)
}

// maskTokenFrom extracts the raw mask token from a request.
//
// The HttpOnly cookie set by the exchange is preferred: it keeps the token out
// of JavaScript entirely. The Authorization header remains accepted so that
// service-to-service callers and tests can present a token directly.
func maskTokenFrom(r *http.Request, cookieName string) string {
	if cookie, err := r.Cookie(cookieName); err == nil {
		if value := strings.TrimSpace(cookie.Value); value != "" {
			return value
		}
	}
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

// enforce is the single authorization decision for every acting route.
//
// Order matters: verify the token cryptographically first, so nothing
// downstream ever reads an unauthenticated claim. Then the token's scope
// ceiling, then the live gate. Every failure path denies; there is no branch
// that falls through to allow.
func (h *Handler) enforce(
	w http.ResponseWriter, r *http.Request, policy actingPolicy,
) (*MaskToken, bool) {
	raw := maskTokenFrom(r, h.authCfg.ActingTokenCookie)
	if raw == "" {
		writeJSONError(w, http.StatusUnauthorized, "INVALID_TOKEN", "missing impersonation token")
		return nil, false
	}

	mask, err := h.verifier.Verify(r.Context(), raw)
	if err != nil {
		if errors.Is(err, ErrVerifierUnavailable) {
			slog.Error("impersonation: cannot verify mask token", "error", err)
			writeJSONError(w, http.StatusBadGateway, "VERIFIER_UNAVAILABLE",
				"token verification is temporarily unavailable")
			return nil, false
		}
		// Deliberately generic: the specific validation failure is logged, not
		// returned, so a caller cannot probe for which check failed.
		slog.Warn("impersonation: mask token rejected", "error", err)
		writeJSONError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid impersonation token")
		return nil, false
	}

	// The caller may state which owner it believes this session is for. The
	// impersonation cookie is one name at one path, so a browser holds exactly
	// one acting session across all its tabs; starting a second one for a
	// different owner replaces the first. Without this check the older tab keeps
	// its own heading and quietly renders the newer owner's records - every
	// server-side check passes, because the token really is valid for that
	// owner. Only the tab is wrong, and only the tab can say so.
	//
	// An absent header asserts nothing and is allowed: direct API callers and
	// tests hold no tab state. This resolves a disagreement about which session
	// is in play; it is not an authorization boundary, and the checks that are
	// one all run below regardless.
	if claimed := strings.TrimSpace(r.Header.Get(actingOwnerHeader)); claimed != "" && claimed != mask.Owner {
		slog.Warn("impersonation: caller expected a different owner than the token carries",
			"expected", claimed, "token", mask.Owner, "nominee", mask.Nominee)
		writeJSONError(w, http.StatusConflict, "ACTING_OWNER_MISMATCH",
			"this acting session is for a different owner")
		return nil, false
	}

	// The scope ceiling fixed at mint time. A nominee granted view-only holds a
	// token that never carried the write scope, so this denies before the gate
	// is even consulted.
	if !mask.HasScope(policy.scope) {
		slog.Warn("impersonation: mask token lacks required scope",
			"owner", mask.Owner, "nominee", mask.Nominee, "required", policy.scope)
		h.audit.recordAction(r.Context(), mask.Owner, mask.Nominee, policy.permission,
			actingResourceID(r), false, "token does not carry "+policy.scope)
		writeJSONError(w, http.StatusForbidden, "INSUFFICIENT_SCOPE",
			"impersonation token does not carry "+policy.scope)
		return nil, false
	}

	// The live decision. This is what makes deactivation take effect on the next
	// request rather than at token expiry.
	decision, err := h.gate.permissions(r.Context(), mask.Owner, mask.Nominee)
	if err != nil {
		slog.Error("impersonation: nomination gate call failed",
			"owner", mask.Owner, "nominee", mask.Nominee, "error", err)
		writeJSONError(w, http.StatusBadGateway, "GATE_UNAVAILABLE", "permission check failed")
		return nil, false
	}
	if !decision.Active {
		h.audit.recordAction(r.Context(), mask.Owner, mask.Nominee, policy.permission,
			actingResourceID(r), false, "no active nomination")
		writeJSONError(w, http.StatusForbidden, "NOT_ACTIVE_NOMINEE",
			"no active nomination for this owner")
		return nil, false
	}
	if !hasPermission(decision.Permissions, policy.permission) {
		h.audit.recordAction(r.Context(), mask.Owner, mask.Nominee, policy.permission,
			actingResourceID(r), false, "permission not granted")
		writeJSONError(w, http.StatusForbidden, "PERMISSION_DENIED",
			"owner did not grant "+policy.permission+" to this nominee")
		return nil, false
	}

	h.audit.recordAction(r.Context(), mask.Owner, mask.Nominee, policy.permission,
		actingResourceID(r), true, "")
	return mask, true
}

// actingResourceID names the consent an action targets, where the route has one.
// A listing targets no single resource and reports none.
func actingResourceID(r *http.Request) string {
	return strings.TrimSpace(r.PathValue("consentId"))
}

// actingRequest returns a request carrying the verified delegation as the
// principal, so downstream proxying derives the tenant from the token rather
// than from anything the client sent.
func actingRequest(r *http.Request, mask *MaskToken) *http.Request {
	return r.WithContext(systemcontext.WithPrincipal(r.Context(), systemcontext.Principal{
		UserID: mask.Nominee,
		OrgID:  mask.OrgID,
	}))
}

// ActingListConsents handles GET /acting/consents with a mask token.
// Requires the nominee read scope and a live CONSENT_VIEW grant.
func (h *Handler) ActingListConsents(w http.ResponseWriter, r *http.Request) {
	mask, ok := h.enforce(w, r, policyListConsents)
	if !ok {
		return
	}
	if err := h.svc.Proxy().Forward(w, actingRequest(r, mask), http.MethodGet,
		"/api/v1/consents", func(q url.Values) {
			q.Set("userIds", mask.Owner)
		}, nil); err != nil {
		writeProxyError(w, err)
	}
}

// ActingGetConsent handles GET /acting/consents/{consentId} with a mask token.
// Requires the nominee read scope and a live CONSENT_VIEW grant.
//
// The consent is fetched before it is returned so its owner can be checked. The
// upstream lookup is by id alone and will happily return any consent in the
// organisation, so without this a nominee holding a valid mask token could read
// a consent belonging to somebody who never nominated them, simply by knowing
// its id. A consent owned by anyone else is reported as absent rather than
// forbidden, which keeps the response from confirming that the id exists.
func (h *Handler) ActingGetConsent(w http.ResponseWriter, r *http.Request) {
	mask, ok := h.enforce(w, r, policyListConsents)
	if !ok {
		return
	}
	consentID := strings.TrimSpace(r.PathValue("consentId"))
	if consentID == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_CONSENT_ID", "invalid consent id")
		return
	}

	resp, err := h.svc.Proxy().ForwardRaw(actingRequest(r, mask), http.MethodGet,
		"/api/v1/consents/"+url.PathEscape(consentID), nil, nil)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	if resp.StatusCode == http.StatusOK && !consentBelongsTo(resp.Body, mask.Owner) {
		slog.Warn("impersonation: consent does not belong to the owner",
			"owner", mask.Owner, "nominee", mask.Nominee, "consentId", consentID)
		writeJSONError(w, http.StatusNotFound, "CONSENT_NOT_FOUND", "consent not found")
		return
	}
	if err := h.svc.Proxy().WriteUpstreamResponse(w, resp); err != nil {
		writeProxyError(w, err)
	}
}

// consentBelongsTo reports whether ownerID holds an authorization on the consent
// described by body. A body that cannot be parsed yields false, so a response
// this code does not understand is never treated as the owner's.
func consentBelongsTo(body []byte, ownerID string) bool {
	var consent struct {
		Authorizations []struct {
			UserID string `json:"userId"`
		} `json:"authorizations"`
	}
	if err := json.Unmarshal(body, &consent); err != nil {
		return false
	}
	for _, authorization := range consent.Authorizations {
		if authorization.UserID == ownerID {
			return true
		}
	}
	return false
}

// ActingApproveConsent handles POST /acting/consents/{consentId}/approve.
// Requires the nominee approve scope and a live CONSENT_APPROVE grant.
//
// Approving is separated from revoking throughout - a distinct permission and a
// distinct scope - because the two are opposite acts. Revoking withdraws
// processing the owner already chose; approving authorises new processing on
// their behalf. Granting one must never confer the other.
//
// The consent is fetched and its owner confirmed before anything is written, for
// the same reason as the detail route: the upstream lookup is by id alone.
func (h *Handler) ActingApproveConsent(w http.ResponseWriter, r *http.Request) {
	mask, ok := h.enforce(w, r, policyApproveConsent)
	if !ok {
		return
	}
	consentID := strings.TrimSpace(r.PathValue("consentId"))
	if consentID == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_CONSENT_ID", "invalid consent id")
		return
	}

	body, err := readBoundedBody(r)
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request entity too large")
		return
	}
	selections, err := me.ParseApprovalSelections(body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid request payload")
		return
	}

	acting := actingRequest(r, mask)
	current, err := h.svc.Proxy().ForwardRaw(acting, http.MethodGet,
		"/api/v1/consents/"+url.PathEscape(consentID), nil, nil)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	if current.StatusCode != http.StatusOK {
		h.svc.Proxy().WriteUpstreamResponse(w, current)
		return
	}
	if !consentBelongsTo(current.Body, mask.Owner) {
		slog.Warn("impersonation: consent does not belong to the owner",
			"owner", mask.Owner, "nominee", mask.Nominee, "consentId", consentID)
		writeJSONError(w, http.StatusNotFound, "CONSENT_NOT_FOUND", "consent not found")
		return
	}

	// The approval is recorded against the OWNER, whose consent it is. Who
	// performed it is carried by the audit trail, which names the nominee.
	payload, trustedGroupID, err := h.svc.Me().BuildApprovalUpdatePayload(
		current.Body, selections, mask.Owner)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid request payload")
		return
	}
	if err := h.svc.Proxy().ForwardWithGroupID(w, acting, http.MethodPut,
		"/api/v1/consents/"+url.PathEscape(consentID), nil, payload, trustedGroupID); err != nil {
		writeProxyError(w, err)
	}
}

// ActingRevokeConsent handles POST /acting/consents/{consentId}/revoke with a
// mask token. Requires the nominee write scope and a live CONSENT_REVOKE grant -
// a view-only nominee is blocked here, before the Consent Server is touched.
//
// actionBy is the nominee, never the owner: the audit trail must name the real
// human who acted.
func (h *Handler) ActingRevokeConsent(w http.ResponseWriter, r *http.Request) {
	mask, ok := h.enforce(w, r, policyRevokeConsent)
	if !ok {
		return
	}
	consentID := strings.TrimSpace(r.PathValue("consentId"))
	if consentID == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_CONSENT_ID", "invalid consent id")
		return
	}
	payload, err := json.Marshal(map[string]any{"actionBy": mask.Nominee})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not build request")
		return
	}

	// The consent is read first for two reasons: to confirm it belongs to the
	// owner this token names, and to obtain the group id the Consent Server
	// requires on a write. A revoke addressed by id alone would reach any
	// consent in the organisation.
	acting := actingRequest(r, mask)
	current, err := h.svc.Proxy().ForwardRaw(acting, http.MethodGet,
		"/api/v1/consents/"+url.PathEscape(consentID), nil, nil)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	if current.StatusCode != http.StatusOK {
		h.svc.Proxy().WriteUpstreamResponse(w, current)
		return
	}
	trustedGroupID, owned, err := me.OwnedConsentGroupID(current.Body, mask.Owner)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	if !owned {
		slog.Warn("impersonation: consent does not belong to the owner",
			"owner", mask.Owner, "nominee", mask.Nominee, "consentId", consentID)
		writeJSONError(w, http.StatusNotFound, "CONSENT_NOT_FOUND", "consent not found")
		return
	}

	if err := h.svc.Proxy().ForwardWithGroupID(w, acting, http.MethodPost,
		"/api/v1/consents/"+url.PathEscape(consentID)+"/revoke", nil, payload,
		trustedGroupID); err != nil {
		writeProxyError(w, err)
	}
}
