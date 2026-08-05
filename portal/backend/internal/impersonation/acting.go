/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

package impersonation

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/system/auth"
)

// Cookie names for the acting session. Separate from the login cookies so that
// ending an acting session can never disturb the nominee's own login, and so a
// mask token can never be mistaken for a first-party access token.
const (
	actingStateCookie = "portal-acting-state"
	actingTokenCookie = "portal-acting-token"
)

// actingStateMaxAge bounds how long a started acting flow may sit unfinished.
// The subject_token IS mints is itself short-lived, so there is no reason to
// keep the state around longer than the round trip needs.
const actingStateMaxAge = 5 * time.Minute

// nomineeScopes are requested at mint time. They are a ceiling REQUEST, not a
// grant: Identity Server first narrows them to what the owner may do, then the
// nomination validator narrows them again to what the owner granted this
// specific nominee.
//
// Only :self scopes appear here. An impersonation token carries the owner as
// its subject, so ":self" resolves to the owner's data - which is exactly the
// boundary a nominee must stay inside.
var nomineeScopes = auth.DelegatableScopes

type actingExchangeRequest struct {
	SubjectToken string `json:"subjectToken"`
	State        string `json:"state"`
}

type actingSessionResponse struct {
	OwnerID   string   `json:"ownerId"`
	NomineeID string   `json:"nomineeId"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expiresAt"`
}

// randomToken returns URL-safe entropy for state and nonce values.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// StartActing handles GET /acting/start?ownerId=... as a top-level browser
// navigation, redirecting to IS's authorization endpoint.
//
// It must be a real navigation, not fetch(): the request has to carry IS's
// session cookie, and the response is a cross-origin redirect whose fragment
// only the browser can read.
func (h *Handler) StartActing(w http.ResponseWriter, r *http.Request) {
	ownerID := strings.TrimSpace(r.URL.Query().Get("ownerId"))
	if ownerID == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "ownerId is required")
		return
	}

	state, err := randomToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not start acting session")
		return
	}
	nonce, err := randomToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not start acting session")
		return
	}

	authorizeURL, err := h.svc.IS().AuthorizeURL(ownerID, state, nonce, nomineeScopes)
	if err != nil {
		writeISError(w, err)
		return
	}

	// The state cookie binds the callback to this browser. It carries the owner
	// so the exchange can report which acting session was established without
	// trusting anything the callback supplies.
	h.setCookie(w, r, actingStateCookie, state+"|"+ownerID, actingStateMaxAge)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// ExchangeActing handles POST /acting/exchange.
//
// The frontend reads subject_token from the URL fragment IS redirected to and
// posts it here. The exchange itself needs the client secret, which is why it
// runs server-side: a subject_token leaked from the fragment is not usable on
// its own.
func (h *Handler) ExchangeActing(w http.ResponseWriter, r *http.Request) {
	body, err := readBoundedBody(r)
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request entity too large")
		return
	}
	var req actingExchangeRequest
	if jsonErr := json.Unmarshal(body, &req); jsonErr != nil ||
		strings.TrimSpace(req.SubjectToken) == "" || strings.TrimSpace(req.State) == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "subjectToken and state are required")
		return
	}

	expectedState, ownerID, err := h.readStateCookie(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_STATE", "no acting flow in progress")
		return
	}
	// Constant-time: state is a secret bound to this browser, so comparing it
	// should not leak position information through timing.
	if subtle.ConstantTimeCompare([]byte(expectedState), []byte(strings.TrimSpace(req.State))) != 1 {
		h.clearCookie(w, r, actingStateCookie)
		writeJSONError(w, http.StatusBadRequest, "INVALID_STATE", "acting state mismatch")
		return
	}
	h.clearCookie(w, r, actingStateCookie)

	subjectToken := strings.TrimSpace(req.SubjectToken)

	// The nominee's own access token, sent to IS as the RFC 8693 actor_token.
	// IS compares its subject against the subject token's may_act claim, so the
	// exchange only succeeds for the nominee actually named in it.
	actorToken, err := auth.CallerAccessToken(r, h.authCfg)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "NOT_AUTHENTICATED",
			"you must be signed in to start an acting session")
		return
	}

	token, err := h.svc.IS().ExchangeSubjectToken(r.Context(), subjectToken, actorToken)
	if err != nil {
		// The client gets a generic error, but the operator needs the reason: a
		// failed exchange is almost always an IS configuration problem and is
		// otherwise invisible from this side.
		slog.Error("impersonation: subject token exchange failed",
			"owner", ownerID, "error", err)
		writeISError(w, err)
		return
	}

	// Verify what we just received rather than trusting the exchange. This also
	// resolves the real owner/nominee pair, which is what the response reports.
	mask, err := h.verifier.Verify(r.Context(), token.AccessToken)
	if err != nil {
		slog.Error("impersonation: exchange returned a token that failed verification", "error", err)
		writeJSONError(w, http.StatusBadGateway, "INVALID_TOKEN",
			"identity server returned an unusable impersonation token")
		return
	}
	// The token must describe the session the browser actually started. A
	// mismatch means the callback was crossed with another flow.
	if ownerID != "" && mask.Owner != ownerID {
		slog.Warn("impersonation: exchanged token subject does not match started session",
			"expected", ownerID, "actual", mask.Owner)
		writeJSONError(w, http.StatusBadRequest, "INVALID_STATE", "acting session mismatch")
		return
	}

	// In subject-token mode the expiry comes from the verified token itself,
	// since no exchange response carried one.
	if token.ExpiresAt.IsZero() {
		token.ExpiresAt = mask.Expiry
	}
	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		writeJSONError(w, http.StatusBadGateway, "INVALID_TOKEN", "identity server returned an expired token")
		return
	}
	h.setCookie(w, r, actingTokenCookie, token.AccessToken, ttl)

	writeJSON(w, http.StatusOK, actingSessionResponse{
		OwnerID:   mask.Owner,
		NomineeID: mask.Nominee,
		Scopes:    scopeList(mask.Scopes),
		ExpiresAt: token.ExpiresAt.Format(time.RFC3339),
	})
}

// StopActing handles POST /acting/stop by clearing the acting cookies.
//
// This ends the session for this browser only. IS cannot revoke an already
// issued impersonation token, which is why its lifetime is kept short and why
// every acting request re-checks the nomination gate regardless.
func (h *Handler) StopActing(w http.ResponseWriter, r *http.Request) {
	h.clearCookie(w, r, actingTokenCookie)
	h.clearCookie(w, r, actingStateCookie)
	w.WriteHeader(http.StatusNoContent)
}

// readStateCookie returns the state and owner recorded when the flow started.
func (h *Handler) readStateCookie(r *http.Request) (state, ownerID string, err error) {
	cookie, err := r.Cookie(actingStateCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", "", errors.New("missing acting state")
	}
	parts := strings.SplitN(cookie.Value, "|", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", errors.New("malformed acting state")
	}
	return parts[0], parts[1], nil
}

// setCookie writes an acting cookie.
//
// HttpOnly: JavaScript never needs to read a mask token, and keeping it out of
// script memory removes the whole XSS exfiltration path.
// SameSite=Strict: an acting session is only ever driven from the portal itself,
// so a cross-site request must never carry the token. This is the CSRF defence
// for the acting routes, which perform state changes.
func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// isSecureRequest reports whether the cookie may carry the Secure attribute.
// Local development runs the portal over plain http, where a Secure cookie would
// simply never be sent back.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func scopeList(scopes map[string]struct{}) []string {
	out := make([]string, 0, len(scopes))
	for scope := range scopes {
		out = append(out, scope)
	}
	return out
}
