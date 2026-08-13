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

// Package identityserver is a SCIM2 client for the WSO2 Identity Server's
// user directory. IS is the sole identity system: it issues login tokens
// (see internal/system/auth) and holds the user directory (this package).
//
// Application-specific attributes (nominee_id, nominee_activated, etc.) are
// nested under a custom SCIM2 schema extension (identityserver.custom_schema_urn).
// That extension must be defined as custom local claims mapped into the SCIM2
// dialect in IS's admin console before these attributes appear on User
// resources; this client cannot provision that configuration itself.
package identityserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

var (
	// ErrUserNotFound is returned when a lookup does not match any user.
	ErrUserNotFound = errors.New("identityserver: user not found")
	// ErrUnavailable is returned when IS cannot be reached or returns a server error.
	ErrUnavailable = errors.New("identityserver: service unavailable")
	// ErrRoleNotFound is returned when a role lookup by name does not match any role.
	ErrRoleNotFound = errors.New("identityserver: role not found")
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

// User is an identity record, flattened for the same StringAttr-style lookup
// the rest of the codebase (nominee/me) already uses - core SCIM2 fields
// (email, given_name, family_name, username) and custom extension attributes
// (nominee_id, nominee_activated, ...) are merged into one flat map.
type User struct {
	ID         string
	Attributes map[string]any
}

// StringAttr returns a named attribute as a string, or "" if absent/not a string.
func (u *User) StringAttr(name string) string {
	if u == nil || u.Attributes == nil {
		return ""
	}
	value, ok := u.Attributes[name].(string)
	if !ok {
		return ""
	}
	return value
}

// SCIM2 User resources mix fixed core fields (id, userName, emails, name) with
// an open-ended extension object keyed by schema URN. Go's json package can't
// express that as a struct, so SCIM documents are handled as map[string]any
// throughout - see toSCIMDocument/fromSCIMDocument below.

type scimListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	Resources    []json.RawMessage `json:"Resources"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Client calls WSO2 IS's SCIM2 user management API using an OAuth2
// client-credentials grant.
type Client struct {
	cfg     config.IdentityServerConfig
	baseURL *url.URL
	http    *http.Client

	tokenMu     sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewClient builds an identity server directory client from app config.
func NewClient(cfg config.IdentityServerConfig) (*Client, error) {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse identityserver.base_url: %w", err)
	}
	return &Client{
		cfg:     cfg,
		baseURL: parsed,
		http: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				//nolint:gosec // dev-only via BFF_IDENTITYSERVER__TLS_SKIP_VERIFY
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
			},
		},
	}, nil
}

// fromSCIMDocument flattens a SCIM2 User resource (core fields + our custom
// schema extension) into the StringAttr-style map the rest of the codebase uses.
func (c *Client) fromSCIMDocument(doc map[string]any) *User {
	id, _ := doc["id"].(string)
	attrs := make(map[string]any)

	if userName, ok := doc["userName"].(string); ok {
		attrs["username"] = userName
	}
	if emails, ok := doc["emails"].([]any); ok {
		for _, raw := range emails {
			if entry, ok := raw.(map[string]any); ok {
				if value, ok := entry["value"].(string); ok && value != "" {
					attrs["email"] = value
					break
				}
			}
		}
	}
	if name, ok := doc["name"].(map[string]any); ok {
		if given, ok := name["givenName"].(string); ok {
			attrs["given_name"] = given
		}
		if family, ok := name["familyName"].(string); ok {
			attrs["family_name"] = family
		}
	}
	if ext, ok := doc[c.cfg.CustomSchemaURN].(map[string]any); ok {
		for k, v := range ext {
			attrs[k] = v
		}
	}

	return &User{ID: id, Attributes: attrs}
}

// knownCoreAttributes are the flat attribute keys mapped onto fixed SCIM2 core
// fields rather than nested under the custom schema extension.
var knownCoreAttributes = map[string]struct{}{
	"username": {}, "email": {}, "password": {}, "given_name": {}, "family_name": {},
}

// toSCIMDocument builds a SCIM2 User document from a flat attribute map,
// routing known core fields to their SCIM2 core paths and everything else
// into the custom schema extension.
func (c *Client) toSCIMDocument(attributes map[string]any) map[string]any {
	doc := map[string]any{
		"schemas": []string{scimUserSchema, c.cfg.CustomSchemaURN},
	}
	if username, ok := attributes["username"].(string); ok && username != "" {
		doc["userName"] = username
	}
	if password, ok := attributes["password"].(string); ok && password != "" {
		doc["password"] = password
	}
	if email, ok := attributes["email"].(string); ok && email != "" {
		doc["emails"] = []map[string]any{{"value": email, "primary": true}}
	}
	givenName, hasGiven := attributes["given_name"].(string)
	familyName, hasFamily := attributes["family_name"].(string)
	if hasGiven || hasFamily {
		name := map[string]any{}
		if hasGiven {
			name["givenName"] = givenName
		}
		if hasFamily {
			name["familyName"] = familyName
		}
		doc["name"] = name
	}

	extension := map[string]any{}
	for k, v := range attributes {
		if _, isCore := knownCoreAttributes[k]; isCore {
			continue
		}
		extension[k] = v
	}
	if len(extension) > 0 {
		doc[c.cfg.CustomSchemaURN] = extension
	}
	return doc
}

// GetUser fetches a user by ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/scim2/Users/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrUserNotFound
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	return c.fromSCIMDocument(doc), nil
}

// CreateUser self-registers a new user directly against IS's SCIM2 endpoint.
func (c *Client) CreateUser(ctx context.Context, attributes map[string]any) (*User, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/scim2/Users", c.toSCIMDocument(attributes))
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode created user: %w", err)
	}
	return c.fromSCIMDocument(doc), nil
}

// UpdateUserAttributes merges the given attributes into the user's existing
// attributes and writes the result back via a SCIM2 PATCH replacing the whole
// custom-schema extension object.
func (c *Client) UpdateUserAttributes(ctx context.Context, id string, patch map[string]any) (*User, error) {
	user, err := c.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]any, len(user.Attributes)+len(patch))
	for k, v := range user.Attributes {
		merged[k] = v
	}
	for k, v := range patch {
		merged[k] = v
	}

	extension := map[string]any{}
	for k, v := range merged {
		if _, isCore := knownCoreAttributes[k]; !isCore {
			extension[k] = v
		}
	}

	payload := map[string]any{
		"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{
			{"op": "replace", "path": c.cfg.CustomSchemaURN, "value": extension},
		},
	}

	status, body, err := c.do(ctx, http.MethodPatch, "/scim2/Users/"+url.PathEscape(id), payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode updated user: %w", err)
	}
	return c.fromSCIMDocument(doc), nil
}

// filterPathFor returns the SCIM2 filter attribute path for a flat attribute
// name: known core attributes map to their SCIM2 core path, everything else
// is schema-qualified under the custom extension per SCIM2 filter syntax.
func (c *Client) filterPathFor(attribute string) string {
	switch attribute {
	case "email":
		return "emails"
	case "username":
		return "userName"
	default:
		return c.cfg.CustomSchemaURN + ":" + attribute
	}
}

// SCIM2 filter operators. Resolving one specific person uses equality; letting
// somebody look a person up uses containment, since a search box that only
// matches a complete address is not a search.
const (
	filterEquals   = "eq"
	filterContains = "co"
)

// findByAttribute returns users whose attribute matches value under op, using
// SCIM2's server-side `filter` query.
func (c *Client) findByAttribute(ctx context.Context, attribute, op, value string) ([]User, error) {
	escaped := strings.ReplaceAll(value, `"`, `\"`)
	query := url.Values{}
	query.Set("filter", fmt.Sprintf(`%s %s "%s"`, c.filterPathFor(attribute), op, escaped))

	status, body, err := c.do(ctx, http.MethodGet, "/scim2/Users?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var page scimListResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode user list: %w", err)
	}
	users := make([]User, 0, len(page.Resources))
	for _, raw := range page.Resources {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("decode user list entry: %w", err)
		}
		users = append(users, *c.fromSCIMDocument(doc))
	}
	return users, nil
}

// FindByNomineeID returns every user whose nominee_id attribute matches the given user ID.
func (c *Client) FindByNomineeID(ctx context.Context, nomineeID string) ([]User, error) {
	return c.findByAttribute(ctx, "nominee_id", filterEquals, nomineeID)
}

// FindByEmail returns the user whose email attribute matches, or ErrUserNotFound.
func (c *Client) FindByEmail(ctx context.Context, email string) (*User, error) {
	users, err := c.findByAttribute(ctx, "email", filterEquals, email)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if strings.EqualFold(users[i].StringAttr("email"), email) {
			return &users[i], nil
		}
	}
	return nil, ErrUserNotFound
}

// Search returns users matching the query by exact email or exact username.
func (c *Client) Search(ctx context.Context, query string) ([]User, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var matches []User
	for _, attribute := range []string{"email", "username"} {
		users, err := c.findByAttribute(ctx, attribute, filterContains, query)
		if err != nil {
			return nil, err
		}
		for i := range users {
			if _, dup := seen[users[i].ID]; dup {
				continue
			}
			seen[users[i].ID] = struct{}{}
			matches = append(matches, users[i])
		}
	}
	return matches, nil
}

// IsUserInRole reports whether userID is a member of the named role, either
// directly or through membership in a group the role is assigned to. Uses IS's
// SCIM2 Roles v2 API (urn:ietf:params:scim:schemas:extension:2.0:Role, which
// carries "users" and "groups" member lists on the role resource).
func (c *Client) IsUserInRole(ctx context.Context, roleName, userID string) (bool, error) {
	roleID, err := c.findRoleIDByName(ctx, roleName)
	if err != nil {
		return false, err
	}

	users, groups, err := c.roleMembers(ctx, roleID)
	if err != nil {
		return false, err
	}
	for _, id := range users {
		if id == userID {
			return true, nil
		}
	}
	for _, groupID := range groups {
		isMember, err := c.groupHasMember(ctx, groupID, userID)
		if err != nil {
			return false, err
		}
		if isMember {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) findRoleIDByName(ctx context.Context, roleName string) (string, error) {
	escaped := strings.ReplaceAll(roleName, `"`, `\"`)
	query := url.Values{}
	query.Set("filter", fmt.Sprintf(`displayName eq "%s"`, escaped))

	status, body, err := c.do(ctx, http.MethodGet, "/scim2/v2/Roles?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var page scimListResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return "", fmt.Errorf("decode role list: %w", err)
	}
	if len(page.Resources) == 0 {
		return "", ErrRoleNotFound
	}
	var role struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(page.Resources[0], &role); err != nil {
		return "", fmt.Errorf("decode role: %w", err)
	}
	return role.ID, nil
}

func (c *Client) roleMembers(ctx context.Context, roleID string) (users []string, groups []string, err error) {
	status, body, err := c.do(ctx, http.MethodGet, "/scim2/v2/Roles/"+url.PathEscape(roleID), nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var role struct {
		Users []struct {
			Value string `json:"value"`
		} `json:"users"`
		Groups []struct {
			Value string `json:"value"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(body, &role); err != nil {
		return nil, nil, fmt.Errorf("decode role: %w", err)
	}
	for _, u := range role.Users {
		users = append(users, u.Value)
	}
	for _, g := range role.Groups {
		groups = append(groups, g.Value)
	}
	return users, groups, nil
}

func (c *Client) groupHasMember(ctx context.Context, groupID, userID string) (bool, error) {
	status, body, err := c.do(ctx, http.MethodGet, "/scim2/Groups/"+url.PathEscape(groupID), nil)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("%w: unexpected status %d", ErrUnavailable, status)
	}
	var group struct {
		Members []struct {
			Value string `json:"value"`
		} `json:"members"`
	}
	if err := json.Unmarshal(body, &group); err != nil {
		return false, fmt.Errorf("decode group: %w", err)
	}
	for _, m := range group.Members {
		if m.Value == userID {
			return true, nil
		}
	}
	return false, nil
}

// do issues a SCIM2 request, retrying once if the directory token is rejected.
//
// The token is cached until its expiry, but the Identity Server can invalidate
// it earlier - on restart, or if it is revoked. Without a retry the cached token
// would keep being sent until it expired on our side, and every directory
// lookup in between would fail.
func (c *Client) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	status, respBody, err := c.doOnce(ctx, method, path, body)
	if err == nil && status == http.StatusUnauthorized {
		c.discardToken()
		return c.doOnce(ctx, method, path, body)
	}
	return status, respBody, err
}

// discardToken forces the next request to fetch a fresh directory token.
func (c *Client) discardToken() {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.cachedToken = ""
	c.tokenExpiry = time.Time{}
}

func (c *Client) doOnce(ctx context.Context, method, path string, body any) (status int, respBody []byte, err error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return 0, nil, err
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("encode request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	relative, err := url.Parse(path)
	if err != nil {
		return 0, nil, fmt.Errorf("parse request path: %w", err)
	}

	target := *c.baseURL
	target.Path = strings.TrimRight(c.baseURL.Path, "/") + relative.Path
	target.RawQuery = relative.RawQuery

	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		slog.Error("identityserver: scim2 call diagnostic", "method", method, "url", target.String(),
			"status", resp.StatusCode, "body", string(respBody), "tokenPrefix", token[:min(20, len(token))])
	}
	return resp.StatusCode, respBody, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	tokenURL := *c.baseURL
	tokenURL.Path = strings.TrimRight(c.baseURL.Path, "/") + "/oauth2/token"

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", c.cfg.DirectoryScopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: token request failed with status %d", ErrUnavailable, resp.StatusCode)
	}

	var token tokenResponse
	if err := json.Unmarshal(respBody, &token); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if token.AccessToken == "" {
		return "", fmt.Errorf("%w: token response missing access_token", ErrUnavailable)
	}

	const expiryLeeway = 60 * time.Second
	c.cachedToken = token.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn)*time.Second - expiryLeeway)

	return c.cachedToken, nil
}
