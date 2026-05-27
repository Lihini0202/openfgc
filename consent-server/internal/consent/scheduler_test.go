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
	"testing"
	"time"

	"github.com/wso2/openfgc/internal/consent/model"
	"github.com/wso2/openfgc/internal/system/error/serviceerror"
)

// signalingExpirationService satisfies ExpirationService and signals when GetExpiredConsents is called.
type signalingExpirationService struct {
	fired chan struct{}
}

func (s *signalingExpirationService) GetExpiredConsents(_ context.Context, _ int64, _ []string) ([]model.Consent, *serviceerror.ServiceError) {
	select {
	case s.fired <- struct{}{}:
	default:
	}
	return []model.Consent{}, nil
}

func (s *signalingExpirationService) ExpireConsent(_ context.Context, _ *model.Consent, _ string) error {
	return nil
}

// TestStartScheduler_FiresJobOnTick verifies that StartScheduler launches RunExpirationJob on each ticker tick.
func TestStartScheduler_FiresJobOnTick(t *testing.T) {
	svc := &signalingExpirationService{fired: make(chan struct{}, 1)}
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go StartScheduler(ctx, svc, 50*time.Millisecond, statuses)

	select {
	case <-svc.fired:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not fire the expiration job within 2 seconds")
	}
}

// TestExpirationStatuses_Fields confirms ExpirationStatuses carries its status list correctly.
func TestExpirationStatuses_Fields(t *testing.T) {
	statuses := ExpirationStatuses{
		ExpirableConsentStatuses: []string{"ACTIVE", "CREATED"},
	}

	if len(statuses.ExpirableConsentStatuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses.ExpirableConsentStatuses))
	}
	if statuses.ExpirableConsentStatuses[0] != "ACTIVE" {
		t.Errorf("expected ACTIVE, got %s", statuses.ExpirableConsentStatuses[0])
	}
	if statuses.ExpirableConsentStatuses[1] != "CREATED" {
		t.Errorf("expected CREATED, got %s", statuses.ExpirableConsentStatuses[1])
	}
}
