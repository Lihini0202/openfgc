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

package context

import (
	"context"
	"testing"
)

func TestPrincipalContextRoundTrip(t *testing.T) {
	want := Principal{
		UserID: "user-1",
		OrgID:  "org-1",
		Scopes: map[string]struct{}{"consents:read:self": {}},
	}

	got, ok := PrincipalFromContext(WithPrincipal(context.Background(), want))
	if !ok {
		t.Fatal("expected principal in context")
	}
	if got.UserID != want.UserID || got.OrgID != want.OrgID {
		t.Fatalf("unexpected principal: %#v", got)
	}
	if _, ok := got.Scopes["consents:read:self"]; !ok {
		t.Fatal("expected principal scopes to be preserved")
	}
}

func TestPrincipalFromContextRejectsMissingIdentity(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		principal Principal
	}{
		{name: "nil context", ctx: nil},
		{name: "missing principal", ctx: context.Background()},
		{name: "missing user", ctx: context.Background(), principal: Principal{OrgID: "org-1"}},
		{name: "missing organization", ctx: context.Background(), principal: Principal{UserID: "user-1"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.ctx
			if test.principal.UserID != "" || test.principal.OrgID != "" {
				ctx = WithPrincipal(ctx, test.principal)
			}
			if _, ok := PrincipalFromContext(ctx); ok {
				t.Fatal("expected principal lookup to fail")
			}
		})
	}
}
