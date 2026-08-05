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

package middleware

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsValidCorrelationID_RejectsNonASCIICharacters(t *testing.T) {
	if isValidCorrelationID("request-１２３") {
		t.Fatal("expected full-width digits to be rejected")
	}
	if isValidCorrelationID("request-αβγ") {
		t.Fatal("expected non-ASCII letters to be rejected")
	}
}

func TestNewCorrelationID_UsesUniqueFallbackWhenRandomFails(t *testing.T) {
	originalRandomRead := randomRead
	randomRead = func(_ []byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	t.Cleanup(func() {
		randomRead = originalRandomRead
	})

	first := newCorrelationID()
	second := newCorrelationID()

	if first == second {
		t.Fatalf("expected unique fallback ids, got same value %q", first)
	}
	if !isValidCorrelationID(first) {
		t.Fatalf("expected first fallback id to be valid, got %q", first)
	}
	if !isValidCorrelationID(second) {
		t.Fatalf("expected second fallback id to be valid, got %q", second)
	}
}

func TestCorrelationIDMiddleware_UsesValidClientID(t *testing.T) {
	const clientID = "client-req.123:abc_DEF"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Correlation-ID"); got != clientID {
			t.Fatalf("expected request correlation id %q, got %q", clientID, got)
		}
		w.WriteHeader(http.StatusOK)
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CorrelationID(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Correlation-ID", clientID)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if got := res.Header().Get("X-Correlation-ID"); got != clientID {
		t.Fatalf("expected response correlation id %q, got %q", clientID, got)
	}
}

func TestCorrelationIDMiddleware_RegeneratesInvalidClientID(t *testing.T) {
	invalidID := "bad id with spaces"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Correlation-ID")
		if got == "" {
			t.Fatal("expected generated request correlation id")
		}
		if got == invalidID {
			t.Fatal("expected invalid client id to be replaced")
		}
		w.WriteHeader(http.StatusOK)
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CorrelationID(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Correlation-ID", invalidID)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	got := res.Header().Get("X-Correlation-ID")
	if got == "" {
		t.Fatal("expected response correlation id")
	}
	if got == invalidID {
		t.Fatal("expected invalid client id to be replaced in response")
	}
}

func TestCorrelationIDMiddleware_GeneratesWhenMissing(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Correlation-ID"); got == "" {
			t.Fatal("expected generated request correlation id")
		}
		w.WriteHeader(http.StatusOK)
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CorrelationID(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if got := res.Header().Get("X-Correlation-ID"); got == "" {
		t.Fatal("expected generated response correlation id")
	}
}
