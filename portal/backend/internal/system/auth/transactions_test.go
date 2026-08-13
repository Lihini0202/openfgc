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

import "testing"

func TestLoginTransactionGenerationAndPKCEChallenge(t *testing.T) {
	state, verifier, err := newLoginTransaction()
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 43 || !validPKCEVerifier(verifier) || state == verifier {
		t.Fatalf("unexpected generated transaction values")
	}

	const rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(rfcVerifier); got != rfcChallenge {
		t.Fatalf("PKCE challenge = %q, want %q", got, rfcChallenge)
	}
}

func TestPKCEVerifierAndStateValidation(t *testing.T) {
	valid := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	if !validPKCEVerifier(valid) {
		t.Fatal("valid RFC 7636 verifier rejected")
	}
	for _, verifier := range []string{"short", valid + "!", string(make([]byte, 129))} {
		if validPKCEVerifier(verifier) {
			t.Fatalf("invalid verifier accepted: %q", verifier)
		}
	}
	if !statesMatch("matching-state", "matching-state") || statesMatch("matching-state", "different-state") || statesMatch("", "") {
		t.Fatal("unexpected state comparison result")
	}
}
