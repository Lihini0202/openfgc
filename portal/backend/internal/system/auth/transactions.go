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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const loginTransactionRandomBytes = 32

func newLoginTransaction() (state string, verifier string, err error) {
	state, err = randomBase64URL(loginTransactionRandomBytes)
	if err != nil {
		return "", "", err
	}
	verifier, err = randomBase64URL(loginTransactionRandomBytes)
	if err != nil {
		return "", "", err
	}
	return state, verifier, nil
}

func randomBase64URL(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, character := range verifier {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '.' ||
			character == '_' || character == '~' {
			continue
		}
		return false
	}
	return true
}

func statesMatch(expected, actual string) bool {
	if expected == "" || actual == "" || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func (m *Manager) setLoginTransactionCookies(w http.ResponseWriter, state, verifier string) {
	expiry := time.Now().Add(time.Duration(m.cfg.LoginTransactionMaxAgeSeconds) * time.Second)
	for name, value := range map[string]string{
		m.cfg.OAuthStateCookie:   state,
		m.cfg.PKCEVerifierCookie: verifier,
	} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: value, Path: "/", Expires: expiry,
			MaxAge: m.cfg.LoginTransactionMaxAgeSeconds, Secure: m.cfg.CookieSecure,
			HttpOnly: true, SameSite: parseSameSite(m.cfg.CookieSameSite),
		})
	}
}

func (m *Manager) clearLoginTransactionCookies(w http.ResponseWriter) {
	for _, name := range []string{m.cfg.OAuthStateCookie, m.cfg.PKCEVerifierCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
			Secure: m.cfg.CookieSecure, HttpOnly: true,
			SameSite: parseSameSite(m.cfg.CookieSameSite),
		})
	}
}

func pkceAuthorizationOption(verifier string) oauth2.AuthCodeOption {
	return oauth2.S256ChallengeOption(verifier)
}
