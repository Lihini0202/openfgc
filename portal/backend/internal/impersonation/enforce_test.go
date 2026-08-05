/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

package impersonation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/wso2/openfgc/portal/backend/internal/system/auth"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// testIS is a stand-in Identity Server: it publishes a JWKS and OIDC discovery
// document so MaskVerifier can be exercised against real signature validation
// rather than a stub.
type testIS struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	issuer   string
	audience string
}

func newTestIS(t *testing.T) *testIS {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	is := &testIS{key: key, audience: "portal-client"}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 is.issuer,
			"authorization_endpoint": is.issuer + "/oauth2/authorize",
			"token_endpoint":         is.issuer + "/oauth2/token",
			"jwks_uri":               is.issuer + "/oauth2/jwks",
		})
	})

	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       key.Public(),
				KeyID:     "test-key",
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}},
		})
	})

	is.server = httptest.NewServer(mux)
	is.issuer = is.server.URL
	t.Cleanup(is.server.Close)
	return is
}

// maskClaimSet is the shape of an IS impersonation token.
type maskClaimSet struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	Act      *actor   `json:"act,omitempty"`
	Scope    string   `json:"scope,omitempty"`
}

type actor struct {
	Sub string `json:"sub"`
}

func (is *testIS) sign(t *testing.T, claims maskClaimSet) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: is.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	return raw
}

// validMask returns a well-formed token; individual tests mutate one field to
// isolate exactly which check they are exercising.
func (is *testIS) validMask() maskClaimSet {
	now := time.Now()
	return maskClaimSet{
		Issuer:   is.issuer,
		Subject:  "owner-uuid",
		Audience: []string{is.audience},
		Expiry:   now.Add(5 * time.Minute).Unix(),
		IssuedAt: now.Unix(),
		Act:      &actor{Sub: "nominee-uuid"},
		Scope:    auth.ScopeConsentsReadSelf + " " + auth.ScopeConsentsWriteSelf,
	}
}

func (is *testIS) verifier() *MaskVerifier {
	return NewMaskVerifier(
		config.IdentityServerConfig{
			IssuerURL:    is.issuer,
			MaskAudience: is.audience,
			Timeout:      5 * time.Second,
		},
		config.AuthConfig{AllowedSigningAlgorithms: []string{"RS256"}},
	)
}

func TestMaskVerifierAcceptsValidToken(t *testing.T) {
	is := newTestIS(t)
	token, err := is.verifier().Verify(context.Background(), is.sign(t, is.validMask()))
	if err != nil {
		t.Fatalf("expected valid token to verify, got %v", err)
	}
	if token.Owner != "owner-uuid" {
		t.Errorf("owner = %q, want owner-uuid", token.Owner)
	}
	if token.Nominee != "nominee-uuid" {
		t.Errorf("nominee = %q, want nominee-uuid", token.Nominee)
	}
	if !token.HasScope(auth.ScopeConsentsWriteSelf) {
		t.Errorf("expected write scope to be present")
	}
}

// Without JWKS verification, an attacker could mint any claims they liked.
func TestMaskVerifierRejectsForgedSignature(t *testing.T) {
	is := newTestIS(t)

	attacker := newTestIS(t) // different key entirely
	forged := is.validMask()
	forged.Subject = "victim-uuid"
	raw := attacker.sign(t, forged)

	if _, err := is.verifier().Verify(context.Background(), raw); err == nil {
		t.Fatal("expected a token signed by an unknown key to be rejected")
	}
}

func TestMaskVerifierRejectsUnsignedToken(t *testing.T) {
	is := newTestIS(t)
	// alg=none style payload: header.payload.<empty signature>
	raw := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJvd25lci11dWlkIiwiYWN0Ijp7InN1YiI6Im5vbWluZWUtdXVpZCJ9fQ."

	if _, err := is.verifier().Verify(context.Background(), raw); err == nil {
		t.Fatal("expected an unsigned token to be rejected")
	}
}

func TestMaskVerifierRejectsTokenWithoutActClaim(t *testing.T) {
	is := newTestIS(t)
	claims := is.validMask()
	claims.Act = nil // an ordinary access token, not an impersonation token

	if _, err := is.verifier().Verify(context.Background(), is.sign(t, claims)); err == nil {
		t.Fatal("expected a token without act.sub to be rejected, not treated as the owner's own token")
	}
}

func TestMaskVerifierRejectsSelfImpersonation(t *testing.T) {
	is := newTestIS(t)
	claims := is.validMask()
	claims.Act = &actor{Sub: claims.Subject}

	if _, err := is.verifier().Verify(context.Background(), is.sign(t, claims)); err == nil {
		t.Fatal("expected act.sub == sub to be rejected")
	}
}

func TestMaskVerifierRejectsExpiredToken(t *testing.T) {
	is := newTestIS(t)
	claims := is.validMask()
	claims.Expiry = time.Now().Add(-time.Minute).Unix()

	if _, err := is.verifier().Verify(context.Background(), is.sign(t, claims)); err == nil {
		t.Fatal("expected an expired token to be rejected")
	}
}

func TestMaskVerifierRejectsWrongAudience(t *testing.T) {
	is := newTestIS(t)
	claims := is.validMask()
	claims.Audience = []string{"some-other-client"}

	if _, err := is.verifier().Verify(context.Background(), is.sign(t, claims)); err == nil {
		t.Fatal("expected a token for another audience to be rejected")
	}
}

func TestMaskVerifierUnconfiguredFailsClosed(t *testing.T) {
	verifier := NewMaskVerifier(config.IdentityServerConfig{}, config.AuthConfig{})
	if verifier.Configured() {
		t.Fatal("verifier with no issuer should not report itself configured")
	}
	if _, err := verifier.Verify(context.Background(), "anything"); err == nil {
		t.Fatal("expected an unconfigured verifier to reject every token")
	}
}

func TestParseScopeClaimHandlesBothEncodings(t *testing.T) {
	tests := []struct {
		name string
		raw  any
	}{
		{"space delimited string", "a b c"},
		{"json array", []any{"a", "b", "c"}},
		{"string slice", []string{"a", "b", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scopes := parseScopeClaim(tc.raw)
			for _, want := range []string{"a", "b", "c"} {
				if _, ok := scopes[want]; !ok {
					t.Errorf("scope %q missing from %v", want, scopes)
				}
			}
		})
	}
}

func TestMaskTokenFromPrefersCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/acting/consents", nil)
	r.Header.Set("Authorization", "Bearer header-token")
	r.AddCookie(&http.Cookie{Name: actingTokenCookie, Value: "cookie-token"})

	if got := maskTokenFrom(r); got != "cookie-token" {
		t.Errorf("maskTokenFrom() = %q, want cookie-token", got)
	}
}

func TestMaskTokenFromFallsBackToHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/acting/consents", nil)
	r.Header.Set("Authorization", "Bearer header-token")

	if got := maskTokenFrom(r); got != "header-token" {
		t.Errorf("maskTokenFrom() = %q, want header-token", got)
	}
}

func TestMaskTokenFromIgnoresNonBearer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/acting/consents", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	if got := maskTokenFrom(r); got != "" {
		t.Errorf("maskTokenFrom() = %q, want empty for non-bearer auth", got)
	}
}

func TestHasPermission(t *testing.T) {
	granted := []string{permConsentView}
	if !hasPermission(granted, permConsentView) {
		t.Error("expected granted permission to be found")
	}
	if hasPermission(granted, permConsentRevoke) {
		t.Error("expected ungranted permission to be denied")
	}
}

// A nominee's mask token authorises them for ONE owner's data. The upstream
// lookup is by consent id alone, so the owner check is the only thing standing
// between a valid mask token and any consent in the organisation.
func TestConsentBelongsToOwner(t *testing.T) {
	const owner = "owner-1"

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"owner holds the authorization", `{"authorizations":[{"userId":"owner-1"}]}`, true},
		{"owner among several", `{"authorizations":[{"userId":"other"},{"userId":"owner-1"}]}`, true},
		{"belongs to somebody else", `{"authorizations":[{"userId":"stranger"}]}`, false},
		{"no authorizations at all", `{"authorizations":[]}`, false},
		{"authorizations absent", `{"id":"c1"}`, false},
		{"unparsable body is never the owner's", `not json`, false},
		{"empty body is never the owner's", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := consentBelongsTo([]byte(tt.body), owner); got != tt.want {
				t.Errorf("consentBelongsTo() = %v, want %v", got, tt.want)
			}
		})
	}
}
