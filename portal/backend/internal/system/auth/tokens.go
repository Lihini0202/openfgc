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
	"net/http"
	"strings"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

func splitToken(token string, maxPartBytes int) (string, string, error) {
	if token == "" {
		return "", "", errInvalidCredentials
	}
	midpoint := len(token) / 2
	part1, part2 := token[:midpoint], token[midpoint:]
	if part1 == "" || part2 == "" || len(part1) > maxPartBytes || len(part2) > maxPartBytes {
		return "", "", errInvalidCredentials
	}
	return part1, part2, nil
}

func reconstructToken(part1, part2 string, cfg config.AuthConfig) (string, error) {
	if part1 == "" || part2 == "" || len(part1) > cfg.MaxTokenPartBytes || len(part2) > cfg.MaxTokenPartBytes {
		return "", errInvalidCredentials
	}
	if len(part1)+len(part2) > cfg.MaxReconstructedTokenBytes {
		return "", errInvalidCredentials
	}
	return part1 + part2, nil
}

func bearerPart(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return "", errInvalidCredentials
	}
	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", errInvalidCredentials
	}
	return fields[1], nil
}

func exactlyOneCookie(r *http.Request, name string) (string, error) {
	var values []string
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			values = append(values, cookie.Value)
		}
	}
	if len(values) != 1 || values[0] == "" {
		return "", errInvalidCredentials
	}
	return values[0], nil
}

func (m *Manager) setSplitCookies(w http.ResponseWriter, token, part1Name, part2Name string, part2HTTPOnly bool, expiry time.Time) error {
	part1, part2, err := splitToken(token, m.cfg.MaxTokenPartBytes)
	if err != nil {
		return err
	}
	m.setCookie(w, part1Name, part1, false, expiry)
	m.setCookie(w, part2Name, part2, part2HTTPOnly, expiry)
	return nil
}

func (m *Manager) setCookie(w http.ResponseWriter, name, value string, httpOnly bool, expiry time.Time) {
	maxAge := int(time.Until(expiry).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", Expires: expiry, MaxAge: maxAge,
		Secure: m.cfg.CookieSecure, HttpOnly: httpOnly, SameSite: parseSameSite(m.cfg.CookieSameSite),
	})
}

func (m *Manager) clearTokenCookies(w http.ResponseWriter) {
	names := []string{
		m.cfg.AccessTokenPart1Cookie, m.cfg.AccessTokenPart2Cookie,
		m.cfg.RefreshTokenPart1Cookie, m.cfg.RefreshTokenPart2Cookie,
		m.cfg.IDTokenPart1Cookie, m.cfg.IDTokenPart2Cookie,
		// Signing out must leave no usable credential behind, and a delegated
		// token is a credential for another person's account.
		m.cfg.ActingTokenCookie, m.cfg.ActingStateCookie,
	}
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
			Secure: m.cfg.CookieSecure, HttpOnly: name == m.cfg.AccessTokenPart2Cookie || name == m.cfg.RefreshTokenPart2Cookie,
			SameSite: parseSameSite(m.cfg.CookieSameSite),
		})
	}
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func joinCookieToken(r *http.Request, part1Name, part2Name string, cfg config.AuthConfig) (string, error) {
	part1, err := exactlyOneCookie(r, part1Name)
	if err != nil {
		return "", err
	}
	part2, err := exactlyOneCookie(r, part2Name)
	if err != nil {
		return "", err
	}
	return reconstructToken(part1, part2, cfg)
}

// CallerAccessToken rebuilds the caller's own access token from the request.
//
// Part one arrives in the Authorization header, part two as an HttpOnly cookie;
// neither half is a valid token alone. Delegation needs the whole token because
// the identity server is sent it as the RFC 8693 actor_token, and compares its
// subject against the subject token's may_act claim - which is what stops a
// leaked subject token being redeemed by anyone but the nominee it names.
func CallerAccessToken(r *http.Request, cfg config.AuthConfig) (string, error) {
	part1, err := bearerPart(r)
	if err != nil {
		return "", err
	}
	part2, err := exactlyOneCookie(r, cfg.AccessTokenPart2Cookie)
	if err != nil {
		return "", err
	}
	return reconstructToken(part1, part2, cfg)
}
