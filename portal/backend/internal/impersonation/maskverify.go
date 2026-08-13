/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

package impersonation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// ErrMaskUnverified is returned whenever a mask token fails cryptographic or
// claim validation. The specific reason is deliberately not surfaced to the
// caller - it is logged, never returned - so a probing client cannot use error
// text to distinguish "bad signature" from "wrong audience" from "expired".
var ErrMaskUnverified = errors.New("impersonation: mask token failed verification")

// ErrVerifierUnavailable is returned when IS's discovery/JWKS endpoint cannot be
// reached. Distinct from ErrMaskUnverified because it maps to 502, not 401: the
// token may well be valid, we simply cannot check it right now. Never treated as
// permission to proceed.
var ErrVerifierUnavailable = errors.New("impersonation: token verifier unavailable")

// MaskToken is a verified impersonation token. Every field here has survived
// signature, issuer, audience and expiry validation - nothing in this struct is
// derived from an unverified source.
type MaskToken struct {
	// Owner is the `sub` claim: the data principal being acted for.
	Owner string
	// Nominee is the `act.sub` claim: the real human performing the action.
	// Always populated - a token without it is rejected, never downgraded.
	Nominee string
	// Scopes is the token's `scope` claim, already narrowed by IS to what the
	// owner granted this nominee (see the nomination validator extension).
	Scopes map[string]struct{}
	// Expiry is the verified `exp` claim.
	Expiry time.Time
	// OrgID is the owner's tenant, taken from the token rather than from the
	// caller. Upstream is multi-tenant on this value, so it must never be
	// client-supplied.
	OrgID string
}

// HasScope reports whether the verified token carries a scope.
func (m *MaskToken) HasScope(scope string) bool {
	if m == nil || m.Scopes == nil {
		return false
	}
	_, ok := m.Scopes[scope]
	return ok
}

// MaskVerifier validates impersonation tokens against the Identity Server's
// published JWKS.
//
// Discovery is performed lazily and retried: IS is an external dependency that
// may start after the BFF, and refusing to boot without it would make the whole
// portal depend on an integration only the nominee flow needs. Until discovery
// succeeds every verification fails closed with ErrVerifierUnavailable.
type MaskVerifier struct {
	issuerURL  string
	audience   string
	signingAlg []string
	httpClient *http.Client

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewMaskVerifier builds a verifier for tokens minted by the configured IS.
//
// Issuer and audience fall back to the login-side auth config: the mask token is
// issued by the same IS instance, to the same client, as the portal's own login
// tokens. Explicit identityserver.* values override when a deployment separates
// them.
func NewMaskVerifier(isCfg config.IdentityServerConfig, authCfg config.AuthConfig) *MaskVerifier {
	issuer := strings.TrimSpace(isCfg.IssuerURL)
	if issuer == "" {
		issuer = strings.TrimSpace(authCfg.IssuerURL)
	}
	audience := strings.TrimSpace(isCfg.MaskAudience)
	if audience == "" {
		audience = strings.TrimSpace(authCfg.ResourceAudience)
	}
	algorithms := append([]string(nil), authCfg.AllowedSigningAlgorithms...)
	if len(algorithms) == 0 {
		algorithms = []string{"RS256"}
	}
	timeout := isCfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &MaskVerifier{
		issuerURL:  issuer,
		audience:   audience,
		signingAlg: algorithms,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				//nolint:gosec // dev-only via BFF_IDENTITYSERVER__TLS_SKIP_VERIFY
				TLSClientConfig: &tls.Config{InsecureSkipVerify: isCfg.TLSSkipVerify},
			},
		},
	}
}

// Configured reports whether an issuer is set at all. When false, every
// verification fails - the acting routes are effectively closed, which is the
// correct posture for a deployment that has not configured impersonation.
func (v *MaskVerifier) Configured() bool {
	return v != nil && v.issuerURL != ""
}

// resolve returns a verifier, performing OIDC discovery on first use and
// retrying on every subsequent call until it succeeds.
func (v *MaskVerifier) resolve(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	if !v.Configured() {
		return nil, fmt.Errorf("%w: identityserver issuer is not configured", ErrVerifierUnavailable)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}

	discoveryCtx := oidc.ClientContext(ctx, v.httpClient)
	provider, err := oidc.NewProvider(discoveryCtx, v.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery failed: %w", ErrVerifierUnavailable, err)
	}

	oidcCfg := &oidc.Config{
		ClientID:             v.audience,
		SupportedSigningAlgs: append([]string(nil), v.signingAlg...),
	}
	// An unset audience means the deployment has not told us what to expect.
	// Skipping the check is the only option, but it is a real weakening, so it
	// is surfaced explicitly at config validation time rather than hidden here.
	if v.audience == "" {
		oidcCfg.SkipClientIDCheck = true
	}

	v.verifier = provider.Verifier(oidcCfg)
	return v.verifier, nil
}

// maskPayload is the subset of claims the BFF enforces on.
//
// Both delegation claims are read because IS uses each at a different stage:
//
//	may_act - on the subject token, meaning "this actor MAY act as sub"
//	act     - on the exchanged access token, meaning "this actor DID act as sub"
//
// Either one identifies the same nominee, and either is sufficient evidence that
// IS authorised the delegation. Which one is present depends on the configured
// exchange mode; the enforcement above this layer does not care.
type maskPayload struct {
	Act struct {
		Sub string `json:"sub"`
	} `json:"act"`
	MayAct struct {
		Sub string `json:"sub"`
	} `json:"may_act"`
	Scope any    `json:"scope"`
	OrgID string `json:"org_id"`
}


// Verify authenticates a raw mask token and returns its verified claims.
//
// Validated here: signature against IS's JWKS, issuer, audience, expiry (all by
// go-oidc), plus `sub` and an `act` claim. A token carrying no delegation claim
// is not an impersonation token and is rejected outright - it is never treated
// as an ordinary token belonging to `sub`, which would silently hand the caller
// the owner's whole account.
//
// `act` specifically, never `may_act`. The two are not interchangeable: `act`
// is on the token the exchange issues and means this actor *is* acting, while
// `may_act` is on the subject token and means only that they *may*. The subject
// token reaches the browser in a URL fragment, so it is readable by scripts and
// kept in history; accepting it here would let anyone who obtained it exercise
// the whole grant while skipping the exchange - which is the step where the
// identity server proves the caller is the nominee.
func (v *MaskVerifier) Verify(ctx context.Context, raw string) (*MaskToken, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrMaskUnverified
	}

	verifier, err := v.resolve(ctx)
	if err != nil {
		return nil, err
	}

	verified, err := verifier.Verify(oidc.ClientContext(ctx, v.httpClient), raw)
	if err != nil {
		return nil, ErrMaskUnverified
	}

	owner := strings.TrimSpace(verified.Subject)
	if owner == "" {
		return nil, ErrMaskUnverified
	}

	var payload maskPayload
	if err := verified.Claims(&payload); err != nil {
		return nil, ErrMaskUnverified
	}
	nominee := strings.TrimSpace(payload.Act.Sub)
	if nominee == "" {
		return nil, ErrMaskUnverified
	}
	// An owner acting "for themselves" through the impersonation path is either a
	// misconfiguration or an attempt to launder a normal token into an acting
	// one. Neither should reach a handler.
	if nominee == owner {
		return nil, ErrMaskUnverified
	}

	return &MaskToken{
		Owner:   owner,
		Nominee: nominee,
		Scopes:  parseScopeClaim(payload.Scope),
		Expiry:  verified.Expiry,
		OrgID:   strings.TrimSpace(payload.OrgID),
	}, nil
}

// parseScopeClaim accepts both encodings IS may emit: a space-delimited string
// or a JSON array of strings.
func parseScopeClaim(raw any) map[string]struct{} {
	scopes := map[string]struct{}{}
	switch value := raw.(type) {
	case string:
		for _, scope := range strings.Fields(value) {
			scopes[scope] = struct{}{}
		}
	case []any:
		for _, entry := range value {
			if scope, ok := entry.(string); ok && strings.TrimSpace(scope) != "" {
				scopes[strings.TrimSpace(scope)] = struct{}{}
			}
		}
	case []string:
		for _, scope := range value {
			if strings.TrimSpace(scope) != "" {
				scopes[strings.TrimSpace(scope)] = struct{}{}
			}
		}
	case json.RawMessage:
		var text string
		if err := json.Unmarshal(value, &text); err == nil {
			return parseScopeClaim(text)
		}
		var list []string
		if err := json.Unmarshal(value, &list); err == nil {
			return parseScopeClaim(list)
		}
	}
	return scopes
}
