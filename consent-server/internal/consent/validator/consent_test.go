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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wso2/openfgc/internal/consent/model"
)

func TestValidateConsentCreateRequest_Success(t *testing.T) {
	req := model.ConsentAPIRequest{
		Type: "accounts",
		Authorizations: []model.AuthorizationAPIRequest{
			{Type: "accounts"},
		},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "org-1")
	require.NoError(t, err)
}

func TestValidateConsentCreateRequest_MissingType(t *testing.T) {
	req := model.ConsentAPIRequest{
		Authorizations: []model.AuthorizationAPIRequest{
			{Type: "accounts"},
		},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "type is required")
}

func TestValidateConsentCreateRequest_TypeTooLong(t *testing.T) {
	req := model.ConsentAPIRequest{
		Type: string(make([]byte, 65)),
		Authorizations: []model.AuthorizationAPIRequest{
			{Type: "accounts"},
		},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "type must be at most 64 characters")
}

func TestValidateConsentGetRequest_Success(t *testing.T) {
	err := ValidateConsentGetRequest("consent-123", "org-1")
	require.NoError(t, err)
}

func TestValidateConsentGetRequest_EmptyConsentID(t *testing.T) {
	err := ValidateConsentGetRequest("", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "consent ID cannot be empty")
}

func TestValidateConsentGetRequest_EmptyOrgID(t *testing.T) {
	err := ValidateConsentGetRequest("consent-123", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "organization ID cannot be empty")
}

func TestValidateConsentGetRequest_ConsentIDTooLong(t *testing.T) {
	err := ValidateConsentGetRequest(string(make([]byte, 256)), "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "consent ID too long")
}

func TestValidateConsentGetRequest_OrgIDTooLong(t *testing.T) {
	err := ValidateConsentGetRequest("consent-123", string(make([]byte, 256)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "organization ID too long")
}

func TestValidateConsentCreateRequest_MissingClientID(t *testing.T) {
	req := model.ConsentAPIRequest{
		Type:           "accounts",
		Authorizations: []model.AuthorizationAPIRequest{{Type: "accounts"}},
	}
	err := ValidateConsentCreateRequest(req, "", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "clientID is required")
}

func TestValidateConsentCreateRequest_MissingOrgID(t *testing.T) {
	req := model.ConsentAPIRequest{
		Type:           "accounts",
		Authorizations: []model.AuthorizationAPIRequest{{Type: "accounts"}},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "orgID is required")
}

func TestValidateConsentCreateRequest_MissingAuthType(t *testing.T) {
	req := model.ConsentAPIRequest{
		Type:           "accounts",
		Authorizations: []model.AuthorizationAPIRequest{{Type: ""}},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authorizations[0].type is required")
}

func TestValidateConsentCreateRequest_NegativeValidityTime(t *testing.T) {
	negativeTime := int64(-100)
	req := model.ConsentAPIRequest{
		Type:           "accounts",
		ValidityTime:   &negativeTime,
		Authorizations: []model.AuthorizationAPIRequest{{Type: "accounts"}},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "validityTime must be non-negative")
}

func TestValidateConsentCreateRequest_NegativeFrequency(t *testing.T) {
	negativeFreq := -5
	req := model.ConsentAPIRequest{
		Type:           "accounts",
		Frequency:      &negativeFreq,
		Authorizations: []model.AuthorizationAPIRequest{{Type: "accounts"}},
	}
	err := ValidateConsentCreateRequest(req, "client-1", "org-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "frequency must be non-negative")
}

func TestValidateConsentUpdateRequest_Success(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{Type: "payments"}
	err := ValidateConsentUpdateRequest(req)
	require.NoError(t, err)
}

func TestValidateConsentUpdateRequest_NoFieldsProvided(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one field must be provided")
}

func TestValidateConsentUpdateRequest_TypeTooLong(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{Type: string(make([]byte, 65))}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "type must be at most 64 characters")
}

func TestValidateConsentUpdateRequest_NegativeValidityTime(t *testing.T) {
	negativeTime := int64(-100)
	req := model.ConsentAPIUpdateRequest{ValidityTime: &negativeTime}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "validityTime must be non-negative")
}

func TestValidateConsentUpdateRequest_NegativeFrequency(t *testing.T) {
	negativeFreq := -5
	req := model.ConsentAPIUpdateRequest{Frequency: &negativeFreq}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "frequency must be non-negative")
}

func TestValidateConsentUpdateRequest_MissingAuthType(t *testing.T) {
	auths := []model.AuthorizationAPIRequest{{Type: ""}}
	req := model.ConsentAPIUpdateRequest{Authorizations: auths}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "authorizations[0].type is required")
}

// TestValidateConsentUpdateRequest_DelegationAttrImmutable_Type blocks delegation.type overwrite
func TestValidateConsentUpdateRequest_DelegationAttrImmutable_Type(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{
		Attributes: map[string]string{
			"delegation.type": "parental_biological",
		},
	}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// TestValidateConsentUpdateRequest_DelegationAttrImmutable_PrincipalID blocks principal_id overwrite
func TestValidateConsentUpdateRequest_DelegationAttrImmutable_PrincipalID(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{
		Attributes: map[string]string{
			"delegation.principal_id": "child-user-123",
		},
	}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// TestValidateConsentUpdateRequest_DelegationAttrImmutable_ValidUntil blocks valid_until overwrite
func TestValidateConsentUpdateRequest_DelegationAttrImmutable_ValidUntil(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{
		Attributes: map[string]string{
			"guardian.valid_until": "9999999999",
		},
	}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// TestValidateConsentUpdateRequest_DelegationAttrImmutable_RevocationPolicy blocks policy overwrite
func TestValidateConsentUpdateRequest_DelegationAttrImmutable_RevocationPolicy(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{
		Attributes: map[string]string{
			"guardian.revocation_policy": "SUBJECT_ONLY",
		},
	}
	err := ValidateConsentUpdateRequest(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// TestValidateConsentUpdateRequest_NonDelegationAttr_Allowed allows normal attribute updates
func TestValidateConsentUpdateRequest_NonDelegationAttr_Allowed(t *testing.T) {
	req := model.ConsentAPIUpdateRequest{
		Attributes: map[string]string{
			"custom.attribute": "some-value",
		},
	}
	err := ValidateConsentUpdateRequest(req)
	require.NoError(t, err)
}

// TestValidateDelegation_MinorCannotSelfInitiateParental ensures a minor (caller == principal)
// cannot self-initiate a parental delegation. Only the parent can initiate parental consent.
func TestValidateDelegation_MinorCannotSelfInitiateParental(t *testing.T) {
	attrs := map[string]string{
		model.AttrDelegationType:           "parental_biological",
		model.AttrDelegationPrincipalID:    "child-123",
		model.AttrGuardianValidUntil:       fmt.Sprintf("%d", time.Now().Add(5*365*24*time.Hour).Unix()),
		model.AttrGuardianRevocationPolicy: string(model.RevocationPolicyAny),
	}
	auths := []model.AuthorizationAPIRequest{
		{UserID: "parent-456", Type: "PRIMARY", Delegation: &model.DelegationAPIRequest{
			PrincipalID: "child-123", Type: "parental_biological", CanRevoke: true, CanModify: true,
		}},
	}

	// Case 1: Caller == principal (child trying to self-initiate) — must fail
	err := ValidateDelegationAttributes(attrs, auths, "child-123")
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be initiated by the parent")

	// Case 2: Caller != principal (parent initiating) — must pass
	err = ValidateDelegationAttributes(attrs, auths, "parent-456")
	require.NoError(t, err)
}

// TestValidateDelegation_NonParentalDelegation_CallerCanBePrincipal ensures that
// non-parental delegation types (guardian, carer, power_of_attorney) allow a capable
// adult to proactively initiate delegation over their own data.
func TestValidateDelegation_NonParentalDelegation_CallerCanBePrincipal(t *testing.T) {
	attrs := map[string]string{
		model.AttrDelegationType:           "power_of_attorney",
		model.AttrDelegationPrincipalID:    "adult-123",
		model.AttrGuardianValidUntil:       fmt.Sprintf("%d", time.Now().Add(10*365*24*time.Hour).Unix()),
		model.AttrGuardianRevocationPolicy: string(model.RevocationPolicyBoth),
	}
	auths := []model.AuthorizationAPIRequest{
		{UserID: "attorney-456", Type: "PRIMARY", Delegation: &model.DelegationAPIRequest{
			PrincipalID: "adult-123", Type: "power_of_attorney", CanRevoke: true, CanModify: true,
		}},
	}

	// Caller == principal, but delegation type is power_of_attorney (not parental) — must pass
	// This is a valid scenario: a capable adult setting up PoA over their own data.
	err := ValidateDelegationAttributes(attrs, auths, "adult-123")
	require.NoError(t, err)
}

// TestValidateConsentUpdateRequest_ConvertToSelfConsent_BypassesImmutability verifies
// that convertToSelfConsent=true skips the delegation attribute immutability guard,
// because the service layer will handle the actual deletion and validation.
func TestValidateConsentUpdateRequest_ConvertToSelfConsent_BypassesImmutability(t *testing.T) {
	// With convertToSelfConsent=false, sending delegation attrs in an update must FAIL
	reqBlocked := model.ConsentAPIUpdateRequest{
		Attributes: map[string]string{
			model.AttrDelegationType: "parental_biological",
		},
	}
	reqBlocked.ConvertToSelfConsent = false
	err := ValidateConsentUpdateRequest(reqBlocked)
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable after consent creation")

	// With convertToSelfConsent=true and NO other fields, the validator must PASS
	// (service layer does the real checks: expired? principal? delegated?)
	reqAllowed := model.ConsentAPIUpdateRequest{
		ConvertToSelfConsent: true,
	}
	err = ValidateConsentUpdateRequest(reqAllowed)
	require.NoError(t, err)

	// convertToSelfConsent=true combined with other fields must FAIL
	// (conversion is an exclusive operation)
	reqMixed := model.ConsentAPIUpdateRequest{
		ConvertToSelfConsent: true,
		Attributes: map[string]string{
			model.AttrDelegationType: "parental_biological",
		},
	}
	err = ValidateConsentUpdateRequest(reqMixed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "convertToSelfConsent cannot be combined")
}
