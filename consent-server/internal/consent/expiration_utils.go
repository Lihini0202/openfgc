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

	"github.com/wso2/openfgc/internal/consent/model"
	"github.com/wso2/openfgc/internal/system/config"
	dbmodel "github.com/wso2/openfgc/internal/system/database/model"
	"github.com/wso2/openfgc/internal/system/log"
	"github.com/wso2/openfgc/internal/system/utils"
)

// GetExpiredConsents retrieves all consents whose validity time has passed
// and whose status is in the expirable list.
func (s *consentService) GetExpiredConsents(ctx context.Context, nowMs int64, expirableStatuses []string) ([]model.Consent, error) {
	logger := log.GetLogger().WithContext(ctx)

	consents, err := s.stores.Consent.GetExpiredConsents(nowMs, expirableStatuses)
	if err != nil {
		logger.Error("Failed to fetch expired consents", log.Error(err))
		return nil, err
	}

	return consents, nil
}

// ExpireConsent updates consent and all related auth resources to expired status.
func (s *consentService) ExpireConsent(ctx context.Context, consent *model.Consent, orgID string) error {
	logger := log.GetLogger().WithContext(ctx)
	logger.Debug("Expiring consent",
		log.String("consent_id", consent.ConsentID),
		log.String("org_id", orgID))

	expiredStatusName := string(config.Get().Consent.GetExpiredConsentStatus())
	currentTime := utils.GetCurrentTimeMillis()

	auditID := utils.GenerateUUID()
	reason := "Consent expired based on validityTime"
	actionBy := "SYSTEM"
	previousStatus := consent.CurrentStatus
	audit := &model.ConsentStatusAudit{
		StatusAuditID:  auditID,
		ConsentID:      consent.ConsentID,
		CurrentStatus:  expiredStatusName,
		ActionTime:     currentTime,
		Reason:         &reason,
		ActionBy:       &actionBy,
		PreviousStatus: &previousStatus,
		OrgID:          orgID,
	}

	consentStore := s.stores.Consent
	authResourceStore := s.stores.AuthResource

	err := s.stores.ExecuteTransaction([]func(tx dbmodel.TxInterface) error{
		func(tx dbmodel.TxInterface) error {
			return consentStore.UpdateStatus(tx, consent.ConsentID, orgID, expiredStatusName, currentTime)
		},
		func(tx dbmodel.TxInterface) error {
			sysExpiredStatus := string(config.Get().Consent.GetSystemExpiredAuthStatus())
			return authResourceStore.UpdateAllStatusByConsentID(tx, consent.ConsentID, orgID, sysExpiredStatus, currentTime)
		},
		func(tx dbmodel.TxInterface) error {
			return consentStore.CreateStatusAudit(tx, audit)
		},
	})
	if err != nil {
		logger.Error("Failed to expire consent in transaction",
			log.Error(err),
			log.String("consent_id", consent.ConsentID))
		return err
	}

	consent.CurrentStatus = expiredStatusName
	consent.UpdatedTime = currentTime

	logger.Debug("Consent expired successfully",
		log.String("consent_id", consent.ConsentID),
		log.String("new_status", expiredStatusName))

	return nil
}
