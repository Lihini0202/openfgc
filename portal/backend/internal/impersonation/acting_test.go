/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

package impersonation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/system/auth"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// fakeGate stands in for Nominee Service's nomination gate.
func fakeGate(t *testing.T, decision gateDecision, status int) *gateClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") != "test-gate-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
	}))
	t.Cleanup(server.Close)

	return newGateClient(config.InternalConfig{
		NomineeServiceURL: server.URL,
		GateAPIKey:        "test-gate-key",
		GateTimeout:       5 * time.Second,
	})
}

func handlerFor(t *testing.T, is *testIS, gate *gateClient) *Handler {
	t.Helper()
	return &Handler{
		verifier: is.verifier(),
		gate:     gate,
		authCfg: config.AuthConfig{
			ActingTokenCookie: actingTokenCookie,
			ActingStateCookie: actingStateCookie,
		},
	}
}

func requestWithMaskCookie(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/acting/consents", nil)
	r.AddCookie(&http.Cookie{Name: actingTokenCookie, Value: token})
	return r
}

func TestEnforceAllowsWhenScopeAndPermissionPresent(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView, permConsentRevoke},
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	w := httptest.NewRecorder()
	mask, ok := h.enforce(w, requestWithMaskCookie(is.sign(t, is.validMask())), policyRevokeConsent)
	if !ok {
		t.Fatalf("expected enforce to allow, got status %d body %s", w.Code, w.Body.String())
	}
	if mask.Nominee != "nominee-uuid" {
		t.Errorf("nominee = %q, want nominee-uuid", mask.Nominee)
	}
}

// A view-only nominee holds a token that never carried the write scope. The
// request must be refused before the gate is even consulted.
func TestEnforceDeniesWhenTokenLacksScope(t *testing.T) {
	is := newTestIS(t)
	claims := is.validMask()
	claims.Scope = auth.ScopeConsentsReadSelf // read only
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView, permConsentRevoke},
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, requestWithMaskCookie(is.sign(t, claims)), policyRevokeConsent); ok {
		t.Fatal("expected enforce to deny a token without the write scope")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "INSUFFICIENT_SCOPE") {
		t.Errorf("body = %s, want INSUFFICIENT_SCOPE", w.Body.String())
	}
}

// The revocation path: the token is still cryptographically valid, but the
// administrator has deactivated the nomination since it was minted.
func TestEnforceDeniesWhenNominationDeactivated(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{Active: false}, http.StatusOK)
	h := handlerFor(t, is, gate)

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, requestWithMaskCookie(is.sign(t, is.validMask())), policyListConsents); ok {
		t.Fatal("expected enforce to deny when the nomination is no longer active")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "NOT_ACTIVE_NOMINEE") {
		t.Errorf("body = %s, want NOT_ACTIVE_NOMINEE", w.Body.String())
	}
}

// The owner narrowed the grant after the token was minted.
func TestEnforceDeniesWhenPermissionRevokedAfterMint(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView}, // revoke withdrawn
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, requestWithMaskCookie(is.sign(t, is.validMask())), policyRevokeConsent); ok {
		t.Fatal("expected enforce to deny once the permission was withdrawn")
	}
	if !strings.Contains(w.Body.String(), "PERMISSION_DENIED") {
		t.Errorf("body = %s, want PERMISSION_DENIED", w.Body.String())
	}
}

// An unreachable gate must never be read as permission to proceed.
func TestEnforceFailsClosedWhenGateUnavailable(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{}, http.StatusInternalServerError)
	h := handlerFor(t, is, gate)

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, requestWithMaskCookie(is.sign(t, is.validMask())), policyListConsents); ok {
		t.Fatal("expected enforce to deny when the gate is unavailable")
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

func TestEnforceDeniesForgedToken(t *testing.T) {
	is := newTestIS(t)
	attacker := newTestIS(t)
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView, permConsentRevoke},
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	forged := is.validMask()
	forged.Subject = "victim-uuid"

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, requestWithMaskCookie(attacker.sign(t, forged)), policyRevokeConsent); ok {
		t.Fatal("expected enforce to deny a forged token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestEnforceDeniesMissingToken(t *testing.T) {
	is := newTestIS(t)
	h := handlerFor(t, is, fakeGate(t, gateDecision{}, http.StatusOK))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/acting/consents", nil)
	if _, ok := h.enforce(w, r, policyListConsents); ok {
		t.Fatal("expected enforce to deny a request with no token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestStartActingRequiresOwnerID(t *testing.T) {
	h := &Handler{}
	w := httptest.NewRecorder()
	h.StartActing(w, httptest.NewRequest(http.MethodGet, "/acting/start", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestExchangeActingRejectsMissingState(t *testing.T) {
	h := &Handler{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/acting/exchange",
		strings.NewReader(`{"subjectToken":"abc","state":"xyz"}`))

	h.ExchangeActing(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "INVALID_STATE") {
		t.Errorf("body = %s, want INVALID_STATE", w.Body.String())
	}
}

func TestExchangeActingRejectsStateMismatch(t *testing.T) {
	h := &Handler{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/acting/exchange",
		strings.NewReader(`{"subjectToken":"abc","state":"attacker-state"}`))
	r.AddCookie(&http.Cookie{Name: actingStateCookie, Value: "real-state|owner-uuid"})

	h.ExchangeActing(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "INVALID_STATE") {
		t.Errorf("body = %s, want INVALID_STATE", w.Body.String())
	}
}

func TestExchangeActingRejectsEmptyPayload(t *testing.T) {
	h := &Handler{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/acting/exchange", strings.NewReader(`{}`))

	h.ExchangeActing(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStopActingClearsCookies(t *testing.T) {
	h := &Handler{authCfg: config.AuthConfig{
		ActingTokenCookie: actingTokenCookie,
		ActingStateCookie: actingStateCookie,
	}}
	w := httptest.NewRecorder()
	h.StopActing(w, httptest.NewRequest(http.MethodPost, "/acting/stop", nil))

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	cleared := map[string]bool{}
	for _, cookie := range w.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	for _, name := range []string{actingTokenCookie, actingStateCookie} {
		if !cleared[name] {
			t.Errorf("expected %s to be cleared", name)
		}
	}
}

func TestAuthorizeURLIncludesImpersonationParameters(t *testing.T) {
	client := NewISClient(config.IdentityServerConfig{
		BaseURL:            "https://is.example.com",
		ClientID:           "portal-client",
		RedirectURI:        "https://portal.example.com/acting/callback",
		ImpersonationScope: "internal_user_impersonate",
		Timeout:            time.Second,
	})

	raw, err := client.AuthorizeURL("owner-uuid", "state-value", "nonce-value", nomineeScopes)
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}

	for _, want := range []string{
		"https://is.example.com/oauth2/authorize?",
		"response_type=id_token+subject_token",
		"requested_subject=owner-uuid",
		"internal_user_impersonate",
		"state=state-value",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("authorize URL missing %q\ngot: %s", want, raw)
		}
	}
}

func TestAuthorizeURLRequiresConfiguration(t *testing.T) {
	client := NewISClient(config.IdentityServerConfig{})
	if _, err := client.AuthorizeURL("owner", "state", "nonce", nil); err == nil {
		t.Fatal("expected an error when IS is not configured")
	}

	client = NewISClient(config.IdentityServerConfig{BaseURL: "https://is.example.com"})
	if _, err := client.AuthorizeURL("owner", "state", "nonce", nil); err == nil {
		t.Fatal("expected an error when redirect_uri is not configured")
	}
}

// IS only treats a request as impersonation when subject_token, subject_token_type,
// actor_token AND actor_token_type are all present. Omitting the actor pair makes
// it fall through to the plain federated-exchange path, which then rejects the
// token with the misleading error "subject token is not ACTIVE". Fail early and
// clearly instead.
func TestExchangeRequiresActorToken(t *testing.T) {
	client := NewISClient(config.IdentityServerConfig{
		BaseURL:     "https://is.example.com",
		ClientID:    "portal-client",
		RedirectURI: "https://portal.example.com/acting/callback",
		Timeout:     time.Second,
	})

	if _, err := client.ExchangeSubjectToken(context.Background(), "a-subject-token", ""); err == nil {
		t.Fatal("expected an error when actor_token is missing")
	}
}

func TestExchangeRequiresSubjectToken(t *testing.T) {
	client := NewISClient(config.IdentityServerConfig{
		BaseURL: "https://is.example.com",
		Timeout: time.Second,
	})

	if _, err := client.ExchangeSubjectToken(context.Background(), "", "an-actor-token"); err == nil {
		t.Fatal("expected an error when subject_token is missing")
	}
}

// The exchange must send all four RFC 8693 parameters.
func TestExchangeSendsAllFourTokenExchangeParameters(t *testing.T) {
	var got url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"exchanged","expires_in":300}`))
	}))
	t.Cleanup(server.Close)

	client := NewISClient(config.IdentityServerConfig{BaseURL: server.URL, Timeout: 5 * time.Second})
	if _, err := client.ExchangeSubjectToken(context.Background(), "subj", "actor"); err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	for key, want := range map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":        "subj",
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
		"actor_token":          "actor",
		"actor_token_type":     "urn:ietf:params:oauth:token-type:jwt",
		"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
	} {
		if got.Get(key) != want {
			t.Errorf("%s = %q, want %q", key, got.Get(key), want)
		}
	}
	// Sending scope would be silently filtered against the subject token's ceiling.
	if got.Has("scope") {
		t.Errorf("scope must not be sent; got %q", got.Get("scope"))
	}
}

// A browser holds one acting session across all its tabs, so opening a second
// owner replaces the first. The superseded tab must be told, not handed the
// newer owner's records under its own heading.
func TestEnforceDeniesWhenCallerExpectsADifferentOwner(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView, permConsentRevoke},
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	r := requestWithMaskCookie(is.sign(t, is.validMask()))
	r.Header.Set(actingOwnerHeader, "a-different-owner")

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, r, policyRevokeConsent); ok {
		t.Fatal("expected enforce to refuse a request naming another owner")
	}
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
	if !strings.Contains(w.Body.String(), "ACTING_OWNER_MISMATCH") {
		t.Errorf("body = %s, want ACTING_OWNER_MISMATCH", w.Body.String())
	}
}

func TestEnforceAllowsWhenCallerNamesTheSameOwner(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView, permConsentRevoke},
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	r := requestWithMaskCookie(is.sign(t, is.validMask()))
	r.Header.Set(actingOwnerHeader, "owner-uuid")

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, r, policyRevokeConsent); !ok {
		t.Fatalf("expected enforce to allow, got status %d body %s", w.Code, w.Body.String())
	}
}

// Direct API callers and tests hold no tab state. Stating nothing asserts
// nothing, and must not be read as a mismatch.
func TestEnforceAllowsWhenCallerNamesNoOwner(t *testing.T) {
	is := newTestIS(t)
	gate := fakeGate(t, gateDecision{
		Active:      true,
		Permissions: []string{permConsentView, permConsentRevoke},
	}, http.StatusOK)
	h := handlerFor(t, is, gate)

	w := httptest.NewRecorder()
	if _, ok := h.enforce(w, requestWithMaskCookie(is.sign(t, is.validMask())), policyRevokeConsent); !ok {
		t.Fatalf("expected enforce to allow, got status %d body %s", w.Code, w.Body.String())
	}
}
