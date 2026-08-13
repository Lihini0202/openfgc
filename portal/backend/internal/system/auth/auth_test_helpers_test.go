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

package auth

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

func testAuthConfig(issuer string) config.AuthConfig {
	return config.AuthConfig{
		Enabled: true, IssuerURL: issuer, ClientID: "portal-client", ClientSecret: "secret",
		PortalURL: "http://portal.example/consents", RedirectURI: "http://bff.example/auth/callback",
		PostLogoutRedirectURI: "http://portal.example/", Scopes: []string{"openid", "profile"},
		ResourceAudience: "portal-api", AllowedSigningAlgorithms: []string{"RS256"},
		HTTPTimeout: 5 * time.Second, RefreshTimeout: 5 * time.Second, ClockSkew: 30 * time.Second,
		ScopeClaim: "scope", OrgIDClaim: "org_id", AccessTokenPart1Cookie: "portal-at-p1",
		AccessTokenPart2Cookie: "portal-at-p2", RefreshTokenPart1Cookie: "portal-rt-p1",
		RefreshTokenPart2Cookie: "portal-rt-p2", IDTokenPart1Cookie: "portal-id-p1",
		IDTokenPart2Cookie: "portal-id-p2", OAuthStateCookie: "portal-oauth-state",
		PKCEVerifierCookie: "portal-pkce-verifier", CookieSameSite: "Lax",
		LoginTransactionMaxAgeSeconds: 600, RefreshCookieMaxAgeSeconds: 3600,
		MaxTokenPartBytes: 3800, MaxReconstructedTokenBytes: 7600,
	}
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func cookiesByName(cookies []*http.Cookie) map[string]*http.Cookie {
	result := make(map[string]*http.Cookie, len(cookies))
	for _, cookie := range cookies {
		result[cookie.Name] = cookie
	}
	return result
}

func startLoginTransaction(t *testing.T, manager *Manager) (string, map[string]*http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	manager.Login(recorder, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("login returned %d", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil || location.Query().Get("state") == "" {
		t.Fatalf("login did not return state: %q", recorder.Header().Get("Location"))
	}
	return location.Query().Get("state"), cookiesByName(recorder.Result().Cookies())
}
