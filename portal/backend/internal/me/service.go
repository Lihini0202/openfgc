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

package me

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/wso2/openfgc/portal/backend/internal/proxy"
	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Service contains /me endpoint logic layered on top of proxy transport.
type Service struct {
	proxy *proxy.Service
}

type consentRetrievalResponse struct {
	ID                         string                      `json:"id"`
	Purposes                   []consentPurposeItem        `json:"purposes"`
	CreatedTime                int64                       `json:"createdTime"`
	UpdatedTime                int64                       `json:"updatedTime"`
	GroupID                    string                      `json:"groupId"`
	Type                       string                      `json:"type"`
	Status                     string                      `json:"status"`
	Frequency                  *int                        `json:"frequency,omitempty"`
	ExpirationTime             *int64                      `json:"expirationTime,omitempty"`
	RecurringIndicator         *bool                       `json:"recurringIndicator,omitempty"`
	DataAccessValidityDuration *int64                      `json:"dataAccessValidityDuration,omitempty"`
	Attributes                 map[string]string           `json:"attributes"`
	Authorizations             []consentAuthorizationEntry `json:"authorizations"`
}

type consentPurposeItem struct {
	PurposeID   string               `json:"purposeId"`
	Name        string               `json:"name"`
	Version     string               `json:"version"`
	DisplayName *string              `json:"displayName,omitempty"`
	Description *string              `json:"description,omitempty"`
	Elements    []consentElementItem `json:"elements"`
}

type consentElementItem struct {
	ElementID   string  `json:"elementId"`
	Name        string  `json:"name"`
	Namespace   string  `json:"namespace"`
	Version     string  `json:"version"`
	DisplayName *string `json:"displayName,omitempty"`
	Description *string `json:"description,omitempty"`
	Approved    bool    `json:"approved"`
	Mandatory   bool    `json:"mandatory"`
	Value       any     `json:"value,omitempty"`
}

type consentAuthorizationEntry struct {
	ID          string  `json:"id"`
	UserID      *string `json:"userId,omitempty"`
	Type        string  `json:"type"`
	Status      string  `json:"status"`
	UpdatedTime int64   `json:"updatedTime"`
	Resources   any     `json:"resources,omitempty"`
}

type consentApprovalSelection struct {
	PurposeID      string `json:"purposeId"`
	PurposeVersion string `json:"purposeVersion"`
	ElementID      string `json:"elementId"`
	ElementVersion string `json:"elementVersion"`
}

type consentAuthorizationPayload struct {
	UserID    *string `json:"userId,omitempty"`
	Type      string  `json:"type"`
	Status    string  `json:"status"`
	Resources any     `json:"resources"`
}

type consentUpdateElement struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   string `json:"version"`
	Approved  bool   `json:"approved"`
	Value     any    `json:"value,omitempty"`
}

type consentUpdatePurpose struct {
	Name     string                 `json:"name"`
	Version  string                 `json:"version"`
	Elements []consentUpdateElement `json:"elements"`
}

type consentUpdatePayload struct {
	Type                       string                        `json:"type"`
	ExpirationTime             *int64                        `json:"expirationTime,omitempty"`
	RecurringIndicator         *bool                         `json:"recurringIndicator,omitempty"`
	DataAccessValidityDuration *int64                        `json:"dataAccessValidityDuration,omitempty"`
	Frequency                  *int                          `json:"frequency,omitempty"`
	Purposes                   []consentUpdatePurpose        `json:"purposes"`
	Attributes                 map[string]string             `json:"attributes"`
	Authorizations             []consentAuthorizationPayload `json:"authorizations"`
}

type consentAuthorizationUpdatePayload struct {
	Authorizations []consentAuthorizationPayload `json:"authorizations"`
}

// NewService builds a me service from app config.
func NewService(cfg config.ProxyConfig) (*Service, error) {
	svc, err := proxy.NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &Service{proxy: svc}, nil
}

// Forward forwards to upstream via the shared proxy service.
func (s *Service) Forward(w http.ResponseWriter, r *http.Request, upstreamMethod, upstreamPath string, queryMutator func(url.Values), body []byte) error {
	return s.proxy.Forward(w, r, upstreamMethod, upstreamPath, queryMutator, body)
}

// ForwardWithGroupID forwards to upstream with a trusted group ID.
func (s *Service) ForwardWithGroupID(w http.ResponseWriter, r *http.Request, upstreamMethod, upstreamPath string, queryMutator func(url.Values), body []byte, trustedGroupID string) error {
	return s.proxy.ForwardWithGroupID(w, r, upstreamMethod, upstreamPath, queryMutator, body, trustedGroupID)
}

// ForwardRaw forwards to upstream and returns a caller-managed response.
func (s *Service) ForwardRaw(r *http.Request, upstreamMethod, upstreamPath string, queryMutator func(url.Values), body []byte) (*proxy.UpstreamResponse, error) {
	return s.proxy.ForwardRaw(r, upstreamMethod, upstreamPath, queryMutator, body)
}

// OwnedConsentGroupID verifies consent ownership and returns its trusted group ID.
func OwnedConsentGroupID(body []byte, userID string) (string, bool, error) {
	var consent consentRetrievalResponse
	if err := json.Unmarshal(body, &consent); err != nil {
		return "", false, proxy.ErrUpstreamUnavailable
	}
	userID = strings.TrimSpace(userID)
	for _, authorization := range consent.Authorizations {
		if authorization.UserID != nil && strings.TrimSpace(*authorization.UserID) == userID {
			return strings.TrimSpace(consent.GroupID), true, nil
		}
	}
	return "", false, nil
}

// WriteUpstreamResponse writes an upstream response back to the caller.
func (s *Service) WriteUpstreamResponse(w http.ResponseWriter, resp *proxy.UpstreamResponse) {
	_ = s.proxy.WriteUpstreamResponse(w, resp)
}

func toConsentApprovalKey(purposeID, purposeVersion, elementID, elementVersion string) string {
	return strings.Join([]string{purposeID, purposeVersion, elementID, elementVersion}, "\x00")
}

func buildRevokePayload(in []byte, userID string) ([]byte, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("missing actionBy")
	}

	payload := map[string]any{}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &payload); err != nil {
			return nil, err
		}
		if payload == nil {
			payload = map[string]any{}
		}
	}
	payload["actionBy"] = userID
	return json.Marshal(payload)
}

func parseApprovalSelections(in []byte) ([]consentApprovalSelection, error) {
	if len(in) == 0 {
		return nil, nil
	}
	var selections []consentApprovalSelection
	if err := json.Unmarshal(in, &selections); err != nil {
		return nil, err
	}
	for _, selection := range selections {
		if strings.TrimSpace(selection.PurposeID) == "" ||
			strings.TrimSpace(selection.PurposeVersion) == "" ||
			strings.TrimSpace(selection.ElementID) == "" ||
			strings.TrimSpace(selection.ElementVersion) == "" {
			return nil, errors.New("invalid approval selection")
		}
	}
	return selections, nil
}

// ConsentApprovalSelection is the exported form of an approval selection, for
// callers outside this package.
//
// The delegated flow approves a consent on an owner's behalf, and must produce
// exactly the payload the first-party flow produces - otherwise "approved by the
// owner" and "approved by their nominee" would write different records for the
// same act. Sharing the type is what keeps the two honest.
type ConsentApprovalSelection = consentApprovalSelection

// ParseApprovalSelections is the exported form of parseApprovalSelections, so
// the delegated flow validates a request body by the same rules as this one.
func ParseApprovalSelections(in []byte) ([]ConsentApprovalSelection, error) {
	return parseApprovalSelections(in)
}

// BuildApprovalUpdatePayload builds the consent update payload for an approval action.
func (s *Service) BuildApprovalUpdatePayload(baseBody []byte, selections []consentApprovalSelection, userID string) ([]byte, string, error) {
	var consent consentRetrievalResponse
	if err := json.Unmarshal(baseBody, &consent); err != nil {
		return nil, "", proxy.ErrUpstreamUnavailable
	}

	selectedOptionalElements := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		selectedOptionalElements[toConsentApprovalKey(
			selection.PurposeID,
			selection.PurposeVersion,
			selection.ElementID,
			selection.ElementVersion,
		)] = struct{}{}
	}

	matchedSelections := make(map[string]struct{}, len(selectedOptionalElements))
	updatedPurposes := make([]consentUpdatePurpose, len(consent.Purposes))
	for purposeIndex, purpose := range consent.Purposes {
		updatedPurpose := consentUpdatePurpose{
			Name:     purpose.Name,
			Version:  purpose.Version,
			Elements: make([]consentUpdateElement, len(purpose.Elements)),
		}
		for elementIndex, element := range purpose.Elements {
			approved := element.Approved
			if element.Mandatory {
				approved = true
			} else {
				key := toConsentApprovalKey(purpose.PurposeID, purpose.Version, element.ElementID, element.Version)
				if _, isSelected := selectedOptionalElements[key]; isSelected {
					approved = true
					matchedSelections[key] = struct{}{}
				}
			}
			updatedPurpose.Elements[elementIndex] = consentUpdateElement{
				Name:      element.Name,
				Namespace: element.Namespace,
				Version:   element.Version,
				Approved:  approved,
				Value:     element.Value,
			}
		}
		updatedPurposes[purposeIndex] = updatedPurpose
	}
	if len(matchedSelections) != len(selectedOptionalElements) {
		return nil, "", errors.New("invalid approval selection")
	}

	updatedAuthorizations := make([]consentAuthorizationPayload, 0, len(consent.Authorizations))
	for _, authorization := range consent.Authorizations {
		updatedAuthorizations = append(updatedAuthorizations, consentAuthorizationPayload{
			UserID:    authorization.UserID,
			Type:      authorization.Type,
			Status:    authorization.Status,
			Resources: normalizeAuthorizationResources(authorization.Resources),
		})
	}

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, "", proxy.ErrUpstreamUnavailable
	}
	updatedAuthorization := consentAuthorizationPayload{
		UserID:    &userID,
		Type:      "authorisation",
		Status:    "APPROVED",
		Resources: map[string]any{},
	}
	if index, ok := findAuthorizationIndexToUpdate(consent.Authorizations, userID); ok {
		updatedAuthorizations[index] = updatedAuthorization
	} else {
		updatedAuthorizations = append(updatedAuthorizations, updatedAuthorization)
	}

	payload := consentUpdatePayload{
		Type:                       consent.Type,
		ExpirationTime:             consent.ExpirationTime,
		RecurringIndicator:         consent.RecurringIndicator,
		DataAccessValidityDuration: consent.DataAccessValidityDuration,
		Frequency:                  consent.Frequency,
		Purposes:                   updatedPurposes,
		Attributes:                 consent.Attributes,
		Authorizations:             updatedAuthorizations,
	}
	serializedPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, "", proxy.ErrUpstreamUnavailable
	}
	return serializedPayload, consent.GroupID, nil
}

// BuildRejectionUpdatePayload builds the minimal consent update required to reject a consent.
func (s *Service) BuildRejectionUpdatePayload(baseBody []byte, userID string) ([]byte, string, error) {
	var consent consentRetrievalResponse
	if err := json.Unmarshal(baseBody, &consent); err != nil {
		return nil, "", proxy.ErrUpstreamUnavailable
	}

	if !strings.EqualFold(strings.TrimSpace(consent.Status), "CREATED") {
		return nil, "", errInvalidConsentState
	}

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, "", proxy.ErrUpstreamUnavailable
	}

	updatedAuthorizations := make([]consentAuthorizationPayload, len(consent.Authorizations))
	currentUserFound := false
	for index, authorization := range consent.Authorizations {
		status := authorization.Status
		if authorization.UserID != nil &&
			strings.EqualFold(strings.TrimSpace(*authorization.UserID), userID) {
			status = "REJECTED"
			currentUserFound = true
		}
		updatedAuthorizations[index] = consentAuthorizationPayload{
			UserID:    authorization.UserID,
			Type:      authorization.Type,
			Status:    status,
			Resources: normalizeAuthorizationResources(authorization.Resources),
		}
	}
	if !currentUserFound {
		return nil, "", proxy.ErrUpstreamUnavailable
	}

	payload := consentAuthorizationUpdatePayload{
		Authorizations: updatedAuthorizations,
	}
	serializedPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, "", proxy.ErrUpstreamUnavailable
	}
	return serializedPayload, consent.GroupID, nil
}

func normalizeAuthorizationResources(resources any) any {
	if resources == nil {
		return map[string]any{}
	}
	return resources
}

func findAuthorizationIndexToUpdate(authorizations []consentAuthorizationEntry, userID string) (int, bool) {
	userID = strings.TrimSpace(userID)
	for index, authorization := range authorizations {
		if authorization.UserID != nil && strings.EqualFold(strings.TrimSpace(*authorization.UserID), userID) {
			return index, true
		}
	}
	return -1, false
}
