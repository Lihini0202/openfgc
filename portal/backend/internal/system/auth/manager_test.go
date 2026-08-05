/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * Licensed under the Apache License, Version 2.0.
 */

package auth

import (
	"encoding/json"
	"testing"
)

// A delegated token names the OWNER as its subject and carries the scopes the
// owner granted the nominee, so a scope check cannot distinguish it from the
// owner's own token. First-party routes must refuse it: the nomination is
// re-checked only on the acting routes, so accepting one here would let a
// nominee act as the owner, attribute it to the owner, and keep working after
// the owner revoked the nomination.
func TestDelegatedTokensAreRefusedOnFirstPartyRoutes(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]json.RawMessage
		want   bool
	}{
		{"owner's own token", map[string]json.RawMessage{
			"sub": json.RawMessage(`"owner-1"`)}, false},
		{"exchanged impersonation token", map[string]json.RawMessage{
			"sub": json.RawMessage(`"owner-1"`),
			"act": json.RawMessage(`{"sub":"nominee-1"}`)}, true},
		{"subject token", map[string]json.RawMessage{
			"sub":     json.RawMessage(`"owner-1"`),
			"may_act": json.RawMessage(`{"sub":"nominee-1"}`)}, true},
		{"explicit null is not a delegation", map[string]json.RawMessage{
			"sub": json.RawMessage(`"owner-1"`),
			"act": json.RawMessage(`null`)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := delegated(tt.claims); got != tt.want {
				t.Errorf("delegated() = %v, want %v", got, tt.want)
			}
		})
	}
}
