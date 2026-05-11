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

	"github.com/stretchr/testify/mock"
	"github.com/wso2/openfgc/internal/consent/model"
)

// TestStartScheduler_FiresJobOnTick verifies that StartScheduler launches RunExpirationJob on each ticker tick.
// The scheduler runs until the context is cancelled, allowing clean test termination.
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cleanup

	// StartScheduler runs until context is cancelled; run it concurrently.
	go StartScheduler(ctx, svc, 50*time.Millisecond, statuses)

	select {
	case <-jobFired:
		// Scheduler fired the expiration job — test passes.
		cancel() // Stop the scheduler cleanly
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
