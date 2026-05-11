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
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/wso2/openfgc/internal/consent/model"
)

// ---------------------------------------------------------------------------
// TestStartScheduler_FiresJobOnTick
// Verifies that StartScheduler launches RunExpirationJob on each ticker tick.
// We run the scheduler in a background goroutine (it blocks forever by design)
// and detect the first job invocation via a buffered channel.
// The goroutine is intentionally left running after the test — this is
// acceptable because StartScheduler has no stop mechanism.
// ---------------------------------------------------------------------------
func TestStartScheduler_FiresJobOnTick(t *testing.T) {
	// Use the raw struct (not NewMockConsentService) to avoid the auto-cleanup
	// assertion firing against a goroutine that outlives the test.
	svc := &MockConsentService{}
	statuses := ExpirationStatuses{ExpirableConsentStatuses: []string{"ACTIVE"}}

	jobFired := make(chan struct{}, 1)

	svc.On("GetExpiredConsents",
		mock.Anything,
		mock.AnythingOfType("int64"),
		statuses.ExpirableConsentStatuses,
	).Return([]model.Consent{}, nil).
		Run(func(_ mock.Arguments) {
			// Signal on first invocation only; ignore subsequent ticks.
			select {
			case jobFired <- struct{}{}:
			default:
			}
		})

	// StartScheduler blocks forever; run it concurrently.
	go StartScheduler(svc, 50*time.Millisecond, statuses)

	select {
	case <-jobFired:
		// Scheduler fired the expiration job — test passes.
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not fire the expiration job within 2 seconds")
	}
}

// ---------------------------------------------------------------------------
// TestExpirationStatuses_Fields
// Confirms ExpirationStatuses carries its status list correctly.
// Keeps this test close to the scheduler file where the type is defined.
// ---------------------------------------------------------------------------
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
