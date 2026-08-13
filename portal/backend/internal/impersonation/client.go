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

// Package impersonation talks to a real WSO2 Identity Server instance to mint
// impersonation access tokens via IS's documented two-step token exchange.
// This is a separate system from ThunderID: Thunder remains the everyday
// login IdP for everyone, and IS is only ever called here, narrowly, to
// mint a token for an already-authorized nominee session. Whether a nominee
// may act for a given owner is decided entirely by Nominee Service before
// this client is ever invoked; IS is only asked its own generic question -
// does this actor's role hold the impersonation scope.
package impersonation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// ErrNotConfigured is returned when identityserver.base_url is empty, i.e. the
// IS admin console setup has not been completed yet.
var ErrNotConfigured = errors.New("impersonation: identity server is not configured")

// ErrIdentityServerUnavailable wraps any failure talking to IS.
var ErrIdentityServerUnavailable = errors.New("impersonation: identity server unavailable")

// Token is the IS access token minted via token-exchange, carrying sub=owner
// and act.sub=nominee (the claims themselves are opaque to the BFF; it only
// needs to hand the raw token back to the caller).
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// ISClient performs the two-step impersonation token exchange against IS.
type ISClient struct {
	http *http.Client
	cfg  config.IdentityServerConfig
}

// NewISClient builds an IS client from app config.
func NewISClient(cfg config.IdentityServerConfig) *ISClient {
	return &ISClient{
		cfg: cfg,
		http: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				//nolint:gosec // dev-only via BFF_IDENTITYSERVER__TLS_SKIP_VERIFY
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
			},
		},
	}
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// AuthorizeURL builds IS impersonation step 1: the authorization-endpoint URL the
// nominee's browser must be redirected to.
//
// This step CANNOT be performed server-to-server. IS identifies the impersonator
// from an interactive session (its commonauth cookie), not from a bearer token,
// so the request has to originate in the nominee's browser where that cookie
// lives. The response comes back as a URL fragment, which likewise only the
// browser can read.
//
// The scopes requested here are a ceiling request, not a grant: IS narrows them
// to what the owner may do, and the nomination validator extension narrows them
// again to what the owner granted this specific nominee.
func (c *ISClient) AuthorizeURL(ownerID, state, nonce string, scopes []string) (string, error) {
	if strings.TrimSpace(c.cfg.BaseURL) == "" {
		return "", ErrNotConfigured
	}
	if strings.TrimSpace(c.cfg.RedirectURI) == "" {
		return "", fmt.Errorf("%w: identityserver.redirect_uri is not configured", ErrNotConfigured)
	}

	requested := append([]string{"openid", c.cfg.ImpersonationScope}, scopes...)
	query := url.Values{
		"response_type":     {"id_token subject_token"},
		"client_id":         {c.cfg.ClientID},
		"redirect_uri":      {c.cfg.RedirectURI},
		"requested_subject": {ownerID},
		"scope":             {strings.Join(dedupe(requested), " ")},
		"state":             {state},
		"nonce":             {nonce},
	}
	return strings.TrimRight(c.cfg.BaseURL, "/") + "/oauth2/authorize?" + query.Encode(), nil
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// ExchangeSubjectToken performs IS impersonation step 2: the RFC 8693 exchange
// that turns a subject token into a usable impersonation access token.
//
// actorToken is the nominee's OWN access token, and it is mandatory. Identity
// Server only treats a request as impersonation when all four of subject_token,
// subject_token_type, actor_token and actor_token_type are present; omit the
// actor pair and it silently falls through to the plain federated-exchange path,
// which then fails with "Invalid Subject Token. Subject token is not ACTIVE."
//
// It is also the stronger check: IS compares the actor token's subject against
// the subject token's may_act claim, proving the caller really is the nominee
// named in it rather than merely holding the token.
func (c *ISClient) ExchangeSubjectToken(ctx context.Context, subjectToken, actorToken string) (*Token, error) {
	if strings.TrimSpace(c.cfg.BaseURL) == "" {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(subjectToken) == "" {
		return nil, fmt.Errorf("%w: empty subject_token", ErrIdentityServerUnavailable)
	}
	if strings.TrimSpace(actorToken) == "" {
		return nil, fmt.Errorf("%w: empty actor_token", ErrIdentityServerUnavailable)
	}
	return c.exchangeForAccessToken(ctx, subjectToken, actorToken)
}

// exchangeForAccessToken is IS impersonation step 2: grant_type=token-exchange.
// Returns an access token with sub=owner, act.sub=nominee.
//
// All four of subject_token, subject_token_type, actor_token and actor_token_type
// are required: IS's TokenExchangeGrantHandler.isImpersonationRequest() checks for
// exactly that set, and anything less is not handled as impersonation at all.
//
// No `scope` parameter is sent, deliberately. IS treats the subject_token's scope
// claim as a ceiling and silently drops any requested scope not present in it.
// Sending nothing makes the resulting token inherit the already-narrowed set
// verbatim, with no silent filtering to debug.
func (c *ISClient) exchangeForAccessToken(ctx context.Context, subjectToken, actorToken string) (*Token, error) {
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {subjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"actor_token":          {actorToken},
		"actor_token_type":     {"urn:ietf:params:oauth:token-type:jwt"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}

	var out accessTokenResponse
	if err := c.postForm(ctx, "/oauth2/token", form, &out); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("%w: empty access_token in response", ErrIdentityServerUnavailable)
	}

	expiresIn := out.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // IS's documented default access token lifetime.
	}
	return &Token{
		AccessToken: out.AccessToken,
		ExpiresAt:   time.Now().UTC().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

func (c *ISClient) postForm(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.cfg.BaseURL, "/")+path, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIdentityServerUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIdentityServerUnavailable, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIdentityServerUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d: %s", ErrIdentityServerUnavailable, resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: invalid response body: %w", ErrIdentityServerUnavailable, err)
	}
	return nil
}
