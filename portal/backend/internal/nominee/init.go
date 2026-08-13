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

package nominee

import (
	"net/http"

	"github.com/wso2/openfgc/portal/backend/internal/system/auth"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Initialize sets up the nominee module and registers routes.
func Initialize(mux *http.ServeMux, cfg config.Config, authManager *auth.Manager) error {
	handler, err := NewHandler(cfg)
	if err != nil {
		return err
	}

	mux.Handle("GET /nominees/lookup", authManager.Require(http.HandlerFunc(handler.LookupUserByEmail), auth.ScopeProfileReadSelf))
	// Either standing resolves a name: a user looking up someone they nominated,
	// or an administrator looking at the activation queue, who holds only :any.
	mux.Handle("GET /users/{id}", authManager.RequireAnyScope(http.HandlerFunc(handler.LookupUserByID),
		auth.ScopeProfileReadSelf, auth.ScopeProfileReadAny))

	// Admin routes stand behind two independent barriers:
	//
	//	scope  profile:read:any - this client application may call cross-user APIs
	//	role   PortalAdmin      - this human is a verified administrator
	//
	// Both are required. The scope alone would let any application holding it
	// act administratively; the role alone would ignore what the client was
	// actually authorised to do.
	adminOnly := func(h http.HandlerFunc) http.Handler {
		return authManager.Require(handler.requireAdmin(h), auth.ScopeProfileReadAny)
	}
	mux.Handle("GET /admin/users/search", adminOnly(handler.AdminSearchUsers))

	return nil
}
