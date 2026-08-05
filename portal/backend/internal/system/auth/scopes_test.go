/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * Licensed under the Apache License, Version 2.0.
 */

package auth

import (
	"strings"
	"testing"
)

func TestValidateConfiguredScopesSupportsEmptyPrefix(t *testing.T) {
	if err := validateConfiguredScopesWithPrefix(
		[]string{"openid", "consents:read:self"},
		"",
		[]string{"consents:read:self"},
	); err != nil {
		t.Fatalf("empty scope prefix should be supported: %v", err)
	}
}

func TestValidateConfiguredScopesRejectsUnknownPrefixedScope(t *testing.T) {
	err := validateConfiguredScopesWithPrefix(
		[]string{"openid", "portal:unknown"},
		"portal:",
		[]string{"portal:consents:read:self"},
	)
	if err == nil {
		t.Fatal("expected an unknown prefixed scope to be rejected")
	}
}

func TestCanonicalScopesAreUniqueAndPrefixed(t *testing.T) {
	seen := make(map[string]struct{}, len(AllPortalScopes))
	for _, scope := range AllPortalScopes {
		if strings.TrimSpace(scope) == "" {
			t.Fatal("canonical scope must not be empty")
		}
		if ScopePrefix != "" && !strings.HasPrefix(scope, ScopePrefix) {
			t.Errorf("scope %q does not use prefix %q", scope, ScopePrefix)
		}
		if _, duplicate := seen[scope]; duplicate {
			t.Errorf("duplicate canonical scope %q", scope)
		}
		seen[scope] = struct{}{}
	}
	if len(seen) != 11 {
		t.Fatalf("expected eleven scopes in AllPortalScopes, got %d", len(seen))
	}

	// The administrative scopes must never be granted to placeholder/dev
	// identity, which is what AllPortalScopes feeds.
	for _, admin := range []string{ScopeProfileReadAny, ScopeProfileWriteAny} {
		if _, present := seen[admin]; present {
			t.Errorf("administrative scope %q must not be in AllPortalScopes", admin)
		}
	}
}

// Only :self scopes may be delegated. An impersonation token has the OWNER as
// its subject, so ":self" resolves to the owner's own data - that is precisely
// the boundary a nominee must stay inside. An :any scope in this set would let a
// nominee reach beyond the owner entirely.
func TestDelegatableScopesAreSelfOnly(t *testing.T) {
	if len(DelegatableScopes) != 5 {
		t.Fatalf("expected five delegatable scopes, got %d", len(DelegatableScopes))
	}
	for _, scope := range DelegatableScopes {
		if !strings.HasSuffix(scope, ":self") {
			t.Errorf("delegatable scope %q must end in :self", scope)
		}
		if strings.HasSuffix(scope, ":any") {
			t.Errorf("scope %q is administrative and must never be delegatable", scope)
		}
	}
}

// Every delegatable scope must also be a canonical portal scope.
func TestDelegatableScopesAreCanonical(t *testing.T) {
	canonical := make(map[string]struct{}, len(AllPortalScopes))
	for _, scope := range AllPortalScopes {
		canonical[scope] = struct{}{}
	}
	for _, scope := range DelegatableScopes {
		if _, ok := canonical[scope]; !ok {
			t.Errorf("delegatable scope %q is not a canonical portal scope", scope)
		}
	}
}

func TestEveryAPIRouteHasCanonicalScopePolicy(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{"GET", "/api/consents", ScopeConsentsReadAny},
		{"POST", "/api/consents", ScopeConsentsWriteAny},
		{"GET", "/api/consents/attributes", ScopeConsentsReadAny},
		{"POST", "/api/consents/validate", ScopeConsentsReadAny},
		{"GET", "/api/consents/c1", ScopeConsentsReadAny},
		{"PUT", "/api/consents/c1", ScopeConsentsWriteAny},
		{"GET", "/api/consents/c1/history", ScopeConsentsReadAny},
		{"POST", "/api/consents/c1/revoke", ScopeConsentsWriteAny},
		{"GET", "/api/consents/c1/authorizations", ScopeConsentsReadAny},
		{"POST", "/api/consents/c1/authorizations", ScopeConsentsWriteAny},
		{"GET", "/api/consents/c1/authorizations/a1", ScopeConsentsReadAny},
		{"PUT", "/api/consents/c1/authorizations/a1", ScopeConsentsWriteAny},
		{"GET", "/api/consent-elements", ScopeElementsRead},
		{"POST", "/api/consent-elements", ScopeElementsWrite},
		{"GET", "/api/consent-elements/e1", ScopeElementsRead},
		{"GET", "/api/consent-elements/e1/versions", ScopeElementsRead},
		{"POST", "/api/consent-elements/e1/versions", ScopeElementsWrite},
		{"GET", "/api/consent-elements/e1/versions/v1", ScopeElementsRead},
		{"DELETE", "/api/consent-elements/e1/versions/v1", ScopeElementsWrite},
		{"GET", "/api/consent-purposes", ScopePurposesRead},
		{"POST", "/api/consent-purposes", ScopePurposesWrite},
		{"GET", "/api/consent-purposes/p1", ScopePurposesRead},
		{"GET", "/api/consent-purposes/p1/versions", ScopePurposesRead},
		{"POST", "/api/consent-purposes/p1/versions", ScopePurposesWrite},
		{"GET", "/api/consent-purposes/p1/versions/v1", ScopePurposesRead},
		{"DELETE", "/api/consent-purposes/p1/versions/v1", ScopePurposesWrite},
	}
	known := make(map[string]struct{}, len(AllPortalScopes))
	for _, scope := range AllPortalScopes {
		known[scope] = struct{}{}
	}
	for _, test := range tests {
		got, ok := ScopeForAPIRequest(test.method, test.path)
		if !ok || got != test.want {
			t.Errorf("%s %s: got %q, %v; want %q", test.method, test.path, got, ok, test.want)
		}
		if _, ok := known[got]; !ok {
			t.Errorf("%s %s references unregistered scope %q", test.method, test.path, got)
		}
	}
	for _, test := range []struct{ method, path string }{
		{"PATCH", "/api/consents/c1"},
		{"GET", "/api/unknown"},
		{"GET", "/not-api/consents"},
		{"POST", "/api/consents/c1/export"},
		{"DELETE", "/api/consent-elements/e1"},
	} {
		if scope, ok := ScopeForAPIRequest(test.method, test.path); ok {
			t.Errorf("unexpected policy for %s %s: %q", test.method, test.path, scope)
		}
	}
}

func TestKnownAPIPathIgnoresMethod(t *testing.T) {
	if !isKnownAPIPath("/api/consents/c1/revoke") {
		t.Fatal("documented API path should be known")
	}
	if isKnownAPIPath("/api/consents/c1/export") {
		t.Fatal("undocumented API path should not be known")
	}
}

