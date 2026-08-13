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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/wso2/openfgc/portal/backend/internal/identityserver"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
	systemcontext "github.com/wso2/openfgc/portal/backend/internal/system/context"
)

// Handler serves the nominee route group.
type Handler struct {
	svc *Service
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewHandler creates a nominee handler with an initialized service.
func NewHandler(cfg config.Config) (*Handler, error) {
	svc, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc}, nil
}

// LookupUserByEmail handles GET /nominees/lookup?email=.
// Lets any authenticated user resolve a nominee candidate's email to their
// user ID before submitting a nomination - Nominee Service requires the ID
// upfront and has no directory access of its own.
func (h *Handler) LookupUserByEmail(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.resolveUserID(w, r); !ok {
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "email is required")
		return
	}
	user, err := h.svc.LookupUserByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, identityserver.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "no registered user with that email")
			return
		}
		slog.Error("nominee: lookup by email failed", "email", email, "error", err)
		writeIdentityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// LookupUserByID handles GET /users/{id}.
// Lets any authenticated user resolve an owner/nominee ID they already hold
// (from their own nominations) to a display name/email for the UI.
func (h *Handler) LookupUserByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.resolveUserID(w, r); !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "id is required")
		return
	}
	user, err := h.svc.LookupUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, identityserver.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeIdentityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// AdminSearchUsers handles GET /admin/users/search?q=.
func (h *Handler) AdminSearchUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.resolveUserID(w, r); !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		writeJSON(w, http.StatusOK, []UserSummary{})
		return
	}
	results, err := h.svc.SearchUsers(r.Context(), query)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, results)
}


func (h *Handler) resolveUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal, ok := systemcontext.PrincipalFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return "", false
	}
	return principal.UserID, true
}

// requireAdmin wraps h with a ThunderID admin-role check. It must run behind
// authManager.Require so a Principal already exists in context.
func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := systemcontext.PrincipalFromContext(r.Context())
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			return
		}
		isAdmin, err := h.svc.IsAdmin(r.Context(), principal.UserID)
		if err != nil {
			writeIdentityError(w, err)
			return
		}
		if !isAdmin {
			writeJSONError(w, http.StatusForbidden, "ADMIN_REQUIRED", "this action requires an administrator")
			return
		}
		next(w, r)
	}
}

func writeIdentityError(w http.ResponseWriter, err error) {
	if errors.Is(err, identityserver.ErrUserNotFound) {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	writeJSONError(w, http.StatusBadGateway, "IDENTITY_SERVICE_UNAVAILABLE", "identity service unavailable")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Code: code, Message: message})
}
