/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package consent

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wso2/openfgc/internal/consent/model"
	dbmodel "github.com/wso2/openfgc/internal/system/database/model"
	"github.com/wso2/openfgc/internal/system/stores"
)

// stubConsentStore is a no-op implementation of interfaces.ConsentStore.
// Tests embed this and override only the methods they need.
type stubConsentStore struct {
	expiredConsents []model.Consent
	expiredErr      error
	expireErrMap    map[string]error
	expiredCalls    []string
}

func (s *stubConsentStore) Create(_ dbmodel.TxInterface, _ *model.Consent) error { return nil }
func (s *stubConsentStore) GetByID(_ context.Context, _, _ string) (*model.Consent, error) {
	return nil, nil
}
func (s *stubConsentStore) Search(_ context.Context, _ model.ConsentSearchFilters) ([]model.Consent, int, error) {
	return nil, 0, nil
}
func (s *stubConsentStore) Update(_ dbmodel.TxInterface, _ *model.Consent) error { return nil }
func (s *stubConsentStore) UpdateStatus(_ dbmodel.TxInterface, consentID, _, _ string, _ int64) error {
	if s.expireErrMap != nil {
		if err, ok := s.expireErrMap[consentID]; ok {
			return err
		}
	}
	s.expiredCalls = append(s.expiredCalls, consentID)
	return nil
}
func (s *stubConsentStore) CreateAttributes(_ dbmodel.TxInterface, _ []model.ConsentAttribute) error {
	return nil
}
func (s *stubConsentStore) GetAttributesByConsentID(_ context.Context, _, _ string) ([]model.ConsentAttribute, error) {
	return nil, nil
}
func (s *stubConsentStore) GetAttributesByConsentIDs(_ context.Context, _ []string, _ string) (map[string]map[string]string, error) {
	return nil, nil
}
func (s *stubConsentStore) DeleteAttributesByConsentID(_ dbmodel.TxInterface, _, _ string) error {
	return nil
}
func (s *stubConsentStore) FindConsentIDsByAttributeKey(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubConsentStore) FindConsentIDsByAttribute(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubConsentStore) CreateStatusAudit(_ dbmodel.TxInterface, _ *model.ConsentStatusAudit) error {
	return nil
}
func (s *stubConsentStore) CreateConsentPurposeMapping(_ dbmodel.TxInterface, _, _, _ string) error {
	return nil
}
func (s *stubConsentStore) CheckPurposeUsedInConsents(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (s *stubConsentStore) GetConsentPurposeMappingsByConsentID(_ context.Context, _, _ string) ([]model.ConsentPurposeMapping, error) {
	return nil, nil
}
func (s *stubConsentStore) CreatePurposeElementApproval(_ dbmodel.TxInterface, _ *model.ConsentElementApprovalRecord) error {
	return nil
}
func (s *stubConsentStore) GetPurposeElementApprovalsByConsentID(_ context.Context, _, _ string) ([]model.ConsentElementApprovalRecord, error) {
	return nil, nil
}
func (s *stubConsentStore) DeleteConsentPurposeMappingsByConsentID(_ dbmodel.TxInterface, _, _ string) error {
	return nil
}
func (s *stubConsentStore) DeletePurposeElementApprovalsByConsentID(_ dbmodel.TxInterface, _, _ string) error {
	return nil
}
func (s *stubConsentStore) GetExpiredConsents(nowMs int64, expirableStatuses []string) ([]model.Consent, error) {
	return s.expiredConsents, s.expiredErr
}

// newTestConsentService builds a *consentService wired to the given stub store.
func newTestConsentService(stub *stubConsentStore) *consentService {
	return &consentService{
		stores: &stores.StoreRegistry{
			Consent: stub,
		},
	}
}

// TestRunExpirationJob_NoExpiredConsents
// When GetExpiredConsents returns an empty list, ExpireConsent must never be called.
func TestRunExpirationJob_NoExpiredConsents(t *testing.T) {
	stub := &stubConsentStore{expiredConsents: []model.Consent{}}
	svc := newTestConsentService(stub)
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE", "CREATED"}}

	RunExpirationJob(context.Background(), svc, statuses)

	require.Empty(t, stub.expiredCalls, "ExpireConsent must not be called when no consents are expired")
}

// TestRunExpirationJob_GetExpiredConsentsFails
// When GetExpiredConsents returns an error, the job must abort early and never call ExpireConsent.
func TestRunExpirationJob_GetExpiredConsentsFails(t *testing.T) {
	stub := &stubConsentStore{expiredErr: errors.New("db connection failed")}
	svc := newTestConsentService(stub)
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE"}}

	RunExpirationJob(context.Background(), svc, statuses)

	require.Empty(t, stub.expiredCalls, "ExpireConsent must not be called when GetExpiredConsents fails")
}

// TestRunExpirationJob_ExpiresAllConsents
// When GetExpiredConsents returns N consents, ExpireConsent must be called exactly N times.
func TestRunExpirationJob_ExpiresAllConsents(t *testing.T) {
	stub := &stubConsentStore{
		expiredConsents: []model.Consent{
			{ConsentID: "consent-aaa", OrgID: "org-1", CurrentStatus: "ACTIVE"},
			{ConsentID: "consent-bbb", OrgID: "org-2", CurrentStatus: "ACTIVE"},
		},
		expireErrMap: map[string]error{},
	}
	svc := newTestConsentService(stub)
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE"}}

	RunExpirationJob(context.Background(), svc, statuses)

	require.Len(t, stub.expiredCalls, 2, "ExpireConsent must be called for each expired consent")
	require.Contains(t, stub.expiredCalls, "consent-aaa")
	require.Contains(t, stub.expiredCalls, "consent-bbb")
}

// TestRunExpirationJob_ContinuesOnExpireError
// When ExpireConsent fails for one consent, the job must continue and still attempt the remaining consents.
func TestRunExpirationJob_ContinuesOnExpireError(t *testing.T) {
	stub := &stubConsentStore{
		expiredConsents: []model.Consent{
			{ConsentID: "consent-fail", OrgID: "org-1", CurrentStatus: "ACTIVE"},
			{ConsentID: "consent-ok", OrgID: "org-2", CurrentStatus: "ACTIVE"},
		},
		expireErrMap: map[string]error{
			"consent-fail": errors.New("expire failed"),
		},
	}
	svc := newTestConsentService(stub)
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE"}}

	RunExpirationJob(context.Background(), svc, statuses)

	require.Contains(t, stub.expiredCalls, "consent-ok", "second consent must still be attempted after first fails")
}

// TestRunExpirationJob_PanicRecovery
// A panic inside GetExpiredConsents must be absorbed and must not propagate.
func TestRunExpirationJob_PanicRecovery(t *testing.T) {
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE"}}

	require.NotPanics(t, func() {
		RunExpirationJob(context.Background(), &panicExpirationService{}, statuses)
	})
}

// panicExpirationService satisfies ExpirationService and panics on GetExpiredConsents.
type panicExpirationService struct{}

func (p *panicExpirationService) GetExpiredConsents(_ context.Context, _ int64, _ []string) ([]model.Consent, error) {
	panic("intentional panic for test")
}

func (p *panicExpirationService) ExpireConsent(_ context.Context, _ *model.Consent, _ string) error {
	return nil
}
