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

// Package nominee implements the DPDP-Act nominee feature: an owner may nominate
// another portal user to view and revoke their consents after an admin activates it.
package nominee

import (
	"context"
	"fmt"

	"github.com/wso2/openfgc/portal/backend/internal/identityserver"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Service implements nominee business logic on top of the identity server client.
type Service struct {
	identity      *identityserver.Client
	adminRoleName string
}

// NewService builds a nominee service from app config.
func NewService(cfg config.Config) (*Service, error) {
	identityClient, err := identityserver.NewClient(cfg.IdentityServer)
	if err != nil {
		return nil, err
	}
	return &Service{
		identity:      identityClient,
		adminRoleName: cfg.IdentityServer.AdminRoleName,
	}, nil
}

// IsAdmin reports whether userID holds the configured admin role in the identity server.
// It runs per-request against the resolved Principal's UserID, rather than once at
// sign-in, so a role change takes effect immediately.
func (s *Service) IsAdmin(ctx context.Context, userID string) (bool, error) {
	return s.identity.IsUserInRole(ctx, s.adminRoleName, userID)
}

// UserSummary is a minimal user record for admin search results.
type UserSummary struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// LookupUserByEmail resolves a nominee candidate's email to their user ID,
// for the owner nomination flow (Nominee Service requires the ID upfront).
func (s *Service) LookupUserByEmail(ctx context.Context, email string) (*UserSummary, error) {
	user, err := s.identity.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return &UserSummary{ID: user.ID, Name: displayName(user), Email: user.StringAttr("email")}, nil
}

// LookupUserByID resolves a user ID to a display name/email, for showing a
// readable identity wherever the frontend only has an owner/nominee ID
// (e.g. from Nominee Service, which has no directory access of its own).
func (s *Service) LookupUserByID(ctx context.Context, id string) (*UserSummary, error) {
	user, err := s.identity.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	return &UserSummary{ID: user.ID, Name: displayName(user), Email: user.StringAttr("email")}, nil
}

// SearchUsers searches portal users by name/email/username for the admin search box.
func (s *Service) SearchUsers(ctx context.Context, query string) ([]UserSummary, error) {
	users, err := s.identity.Search(ctx, query)
	if err != nil {
		return nil, err
	}
	results := make([]UserSummary, 0, len(users))
	for i := range users {
		u := &users[i]
		results = append(results, UserSummary{ID: u.ID, Name: displayName(u), Email: u.StringAttr("email")})
	}
	return results, nil
}

func displayName(u *identityserver.User) string {
	given := u.StringAttr("given_name")
	family := u.StringAttr("family_name")
	if given == "" && family == "" {
		if name := u.StringAttr("name"); name != "" {
			return name
		}
		return u.StringAttr("username")
	}
	if given == "" {
		return family
	}
	if family == "" {
		return given
	}
	return fmt.Sprintf("%s %s", given, family)
}
