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

package validator

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	authvalidator "github.com/wso2/openfgc/internal/authresource/validator"
	"github.com/wso2/openfgc/internal/consent/model"
	"github.com/wso2/openfgc/internal/system/config"
)

// ValidateConsentCreateRequest validates consent creation request
func ValidateConsentCreateRequest(req model.ConsentAPIRequest, clientID, orgID string) error {
	// Required fields
	if req.Type == "" {
		return fmt.Errorf("type is required")
	}
	if len(req.Type) > 64 {
		return fmt.Errorf("type must be at most 64 characters")
	}
	if clientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if orgID == "" {
		return fmt.Errorf("orgID is required")
	}

	// Validate auth resources (Authorizations field)
	for i, authReq := range req.Authorizations {
		if authReq.Type == "" {
			return fmt.Errorf("authorizations[%d].type is required", i)
		}
		// Status is optional and defaults to "created" in ToAuthResourceCreateRequest (or "approved" in consent-embedded flows)
		if authReq.Status != "" {
			cfg := config.Get()
			if cfg == nil {
				return fmt.Errorf("configuration not initialized")
			}
			if err := authvalidator.ValidateAuthStatus(authReq.Status, cfg.Consent.AuthStatusMappings); err != nil {
				return fmt.Errorf("authorizations[%d]: %w", i, err)
			}
		}
	}

	// Validate validity time if provided
	if req.ValidityTime != nil && *req.ValidityTime < 0 {
		return fmt.Errorf("validityTime must be non-negative")
	}

	// Validate frequency if provided
	if req.Frequency != nil && *req.Frequency < 0 {
		return fmt.Errorf("frequency must be non-negative")
	}

	return nil
}

// ValidateConsentUpdateRequest validates consent update request (keeping for future use)
func ValidateConsentUpdateRequest(req model.ConsentAPIUpdateRequest) error {
	// At least one field must be provided (check if nil, not if empty)
	if req.Type == "" && req.Frequency == nil &&
		req.ValidityTime == nil && req.RecurringIndicator == nil &&
		req.Attributes == nil && req.Authorizations == nil && req.Purposes == nil &&
		req.DataAccessValidityDuration == nil {
		return fmt.Errorf("at least one field must be provided for update")
	}

	// Validate Type length if provided (match create constraint)
	if req.Type != "" && len(req.Type) > 64 {
		return fmt.Errorf("type must be at most 64 characters")
	}

	// Validate validity time if provided
	if req.ValidityTime != nil && *req.ValidityTime < 0 {
		return fmt.Errorf("validityTime must be non-negative")
	}

	// Validate frequency if provided
	if req.Frequency != nil && *req.Frequency < 0 {
		return fmt.Errorf("frequency must be non-negative")
	}

	// Delegation attributes are immutable after consent creation.
	protectedKeys := []string{
		model.AttrDelegationType,
		model.AttrDelegationPrincipalID,
		model.AttrGuardianValidUntil,
		model.AttrGuardianRevocationPolicy,
	}
	if req.Attributes != nil {
		for _, key := range protectedKeys {
			if _, exists := req.Attributes[key]; exists {
				return fmt.Errorf(
					"delegation attribute '%s' is immutable after consent creation "+
						"and cannot be modified via update", key)
			}
		}
	}

	// Validate auth resources if provided
	if req.Authorizations != nil {
		for i, authReq := range req.Authorizations {
			if authReq.Type == "" {
				return fmt.Errorf("authorizations[%d].type is required", i)
			}
			// Validate auth status if provided
			if authReq.Status != "" {
				cfg := config.Get()
				if cfg == nil {
					return fmt.Errorf("configuration not initialized")
				}
				if err := authvalidator.ValidateAuthStatus(authReq.Status, cfg.Consent.AuthStatusMappings); err != nil {
					return fmt.Errorf("authorizations[%d]: %w", i, err)
				}
			}
		}
	}

	return nil
}

// ValidateConsentGetRequest validates consent retrieval request parameters
func ValidateConsentGetRequest(consentID, orgID string) error {
	if consentID == "" {
		return fmt.Errorf("consent ID cannot be empty")
	}
	if len(consentID) > 255 {
		return fmt.Errorf("consent ID too long (max 255 characters)")
	}
	if orgID == "" {
		return fmt.Errorf("organization ID cannot be empty")
	}
	if len(orgID) > 255 {
		return fmt.Errorf("organization ID too long (max 255 characters)")
	}
	return nil
}

// EvaluateConsentStatusFromAuthStatuses determines consent status from a list of auth status strings.
// This is a helper function for authresource package to avoid import cycles.
// Uses the same priority logic as EvaluateConsentStatus.
func EvaluateConsentStatusFromAuthStatuses(authStatuses []string) string {
	cfg := config.Get()
	if cfg == nil {
		return "created" // safe fallback
	}
	consentConfig := cfg.Consent
	if len(authStatuses) == 0 {
		// No auth resources - default to created status
		return string(consentConfig.GetCreatedConsentStatus())
	}

	// Evaluate ALL auth statuses with priority logic
	hasRejected := false
	hasCreated := false
	allApproved := true

	for _, authStatus := range authStatuses {
		// Map auth status to consent status first (case-insensitive comparison)
		authStatusUpper := strings.ToUpper(authStatus)
		var mappedConsentStatus string

		// Check if auth status matches known auth states
		if authStatusUpper == strings.ToUpper(string(consentConfig.GetApprovedAuthStatus())) || authStatus == "" {
			// Approved or empty/missing status → active consent
			mappedConsentStatus = string(consentConfig.GetActiveConsentStatus())
		} else if authStatusUpper == strings.ToUpper(string(consentConfig.GetRejectedAuthStatus())) {
			// Rejected auth → rejected consent
			mappedConsentStatus = string(consentConfig.GetRejectedConsentStatus())
		} else if authStatusUpper == strings.ToUpper(string(consentConfig.GetCreatedAuthStatus())) {
			// Created auth → created consent
			mappedConsentStatus = string(consentConfig.GetCreatedConsentStatus())
		} else {
			// Unknown status - treat as created
			mappedConsentStatus = string(consentConfig.GetCreatedConsentStatus())
		}

		// Now check the mapped consent status
		if mappedConsentStatus == string(consentConfig.GetRejectedConsentStatus()) {
			hasRejected = true
			allApproved = false
		} else if mappedConsentStatus == string(consentConfig.GetCreatedConsentStatus()) {
			hasCreated = true
			allApproved = false
		} else if mappedConsentStatus != string(consentConfig.GetActiveConsentStatus()) {
			allApproved = false
		}
	}

	// Priority: rejected > created > approved (active)
	if hasRejected {
		return string(consentConfig.GetRejectedConsentStatus())
	} else if hasCreated {
		return string(consentConfig.GetCreatedConsentStatus())
	} else if allApproved {
		return string(consentConfig.GetActiveConsentStatus())
	} else {
		return string(consentConfig.GetCreatedConsentStatus())
	}
}

// IsConsentExpired checks if a given validity time has expired
func IsConsentExpired(validityTime int64) bool {
	if validityTime == 0 {
		return false // No expiry set
	}

	// Detect if timestamp is in seconds or milliseconds
	// A reasonable cutoff: timestamps > 10^11 are likely in milliseconds
	// This works until year 5138 in seconds (safely covers our use case)
	const timestampCutoff = 100000000000 // 10^11

	var validityTimeMillis int64
	if validityTime < timestampCutoff {
		// Timestamp is in seconds, convert to milliseconds
		validityTimeMillis = validityTime * 1000
	} else {
		// Timestamp is already in milliseconds
		validityTimeMillis = validityTime
	}

	currentTimeMillis := time.Now().UnixNano() / int64(time.Millisecond)
	return currentTimeMillis > validityTimeMillis
}

// ValidateDelegationAttributes validates delegation attributes when delegation.type is present.
// No-op for normal self-consented requests.
func ValidateDelegationAttributes(
	attributes map[string]string,
	authorizations []model.AuthorizationAPIRequest,
	callerID string,
) error {
	// Not a delegated consent — skip all delegation checks.
	delegationType := strings.TrimSpace(attributes[model.AttrDelegationType])
	if delegationType == "" {
		return nil
	}
	// Case-insensitive copy for comparisons.
	delegationTypeLower := strings.ToLower(delegationType)

	principalID := strings.TrimSpace(attributes[model.AttrDelegationPrincipalID])
	if principalID == "" {
		return fmt.Errorf(
			"delegation.principal_id is required when delegation.type is set")
	}

	// Required for self-delegation check.
	callerID = strings.TrimSpace(callerID)
	if callerID == "" {
		return fmt.Errorf(
			"caller identity (X-User-ID) is required when delegation.type is set")
	}

	// Delegate userId must not equal the principal (circular self-delegation).
	for _, auth := range authorizations {
		delegateUserID := strings.TrimSpace(auth.UserID)
		if delegateUserID != "" && delegateUserID == principalID {
			return fmt.Errorf(
				"delegate userId '%s' cannot be the same as the data principal; "+
					"a person cannot be delegated authority over their own consent",
				delegateUserID)
		}
	}

	// If caller is the principal, at least one other delegate must exist.
	if callerID == principalID {
		// Guard against a minor self-initiating parental consent.
		// Parental delegation must be initiated by the parent, not the child, per
		// DPDP Section 9 and the stated design requirement.
		// Non-parental delegation types (guardian, carer, power_of_attorney) are still
		// allowed because a capable adult may legitimately initiate those over their own data.
		if delegationTypeLower == "parental" || delegationTypeLower == "parental_biological" || delegationTypeLower == "parental_legal" {
			return fmt.Errorf(
				"parental delegation must be initiated by the parent, not the data principal; "+
					"caller '%s' cannot be the principal for delegation.type '%s'",
				callerID, delegationType)
		}

		hasRealDelegate := false
		for _, auth := range authorizations {
			delegateUserID := strings.TrimSpace(auth.UserID)
			if delegateUserID != "" && delegateUserID != principalID {
				hasRealDelegate = true
				break
			}
		}
		if !hasRealDelegate {
			return fmt.Errorf(
				"when caller is the data principal, at least one authorization must "+
					"register a delegate with a different userId for principal '%s'",
				principalID)
		}
	}

	validUntilStr := strings.TrimSpace(attributes[model.AttrGuardianValidUntil])
	if validUntilStr != "" {
		validUntil, err := strconv.ParseInt(validUntilStr, 10, 64)
		if err != nil || validUntil <= 0 {
			return fmt.Errorf(
				"guardian.valid_until must be a valid positive Unix timestamp in seconds")
		}

		// Unix seconds will not exceed 1e11 until the year 5138, so any value
		// larger than that is almost certainly a millisecond value by mistake,
		// which would create a delegation ~1000x longer than intended.
		const maxUnixSeconds = int64(100_000_000_000)
		if validUntil > maxUnixSeconds {
			return fmt.Errorf(
				"guardian.valid_until appears to be in milliseconds; provide a Unix timestamp in seconds")
		}
		if time.Now().Unix() >= validUntil {
			return fmt.Errorf(
				"guardian.valid_until must be a future timestamp; " +
					"the delegation would be expired immediately")
		}
	}

	// Validate revocation policy.
	policy := strings.TrimSpace(attributes[model.AttrGuardianRevocationPolicy])
	if policy == "" {
		return fmt.Errorf(
			"guardian.revocation_policy is required for delegated consents; "+
				"valid values: %s, %s or %s",
			model.RevocationPolicyAny,
			model.RevocationPolicySubjectOnly,
			model.RevocationPolicyBoth,
		)
	}
	switch model.RevocationPolicy(policy) {
	case model.RevocationPolicyAny,
		model.RevocationPolicySubjectOnly,
		model.RevocationPolicyBoth:

	default:
		return fmt.Errorf(
			"guardian.revocation_policy must be %s, %s or %s, got: %s",
			model.RevocationPolicyAny,
			model.RevocationPolicySubjectOnly,
			model.RevocationPolicyBoth,
			policy,
		)
	}

	// At least one authorization must have onBehalfOf matching the principal.
	//
	//
	found := false
	for _, auth := range authorizations {
		// Resolve the effective principal from the Delegation struct (new path).
		effectivePrincipal := ""
		if auth.Delegation != nil {
			effectivePrincipal = strings.TrimSpace(auth.Delegation.PrincipalID)
		}

		// Resolve from Resources map (legacy path).
		if resources, ok := auth.Resources.(map[string]interface{}); ok {
			if onBehalfOf, _ := resources["onBehalfOf"].(string); onBehalfOf != "" {
				// If Delegation was also set, the two values must agree.
				if effectivePrincipal != "" && effectivePrincipal != onBehalfOf {
					return fmt.Errorf(
						"authorization delegation principal mismatch: delegation.principalId %q "+
							"does not match resources.onBehalfOf %q",
						effectivePrincipal, onBehalfOf,
					)
				}
				effectivePrincipal = onBehalfOf
			}
		}

		if effectivePrincipal == principalID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf(
			"at least one authorization must include onBehalfOf = %q "+
				"(via resources or delegation.principalId) "+
				"to register a delegate for the data principal", principalID)
	}

	return nil
}
