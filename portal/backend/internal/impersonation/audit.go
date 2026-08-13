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

package impersonation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/wso2/openfgc/portal/backend/internal/system/config"
)

// Audit event names. These match the event types Nominee Service appends to its
// chain, and are the only record of a nominee reading an owner's data or being
// refused: the Consent Server observes successful writes and nothing else.
const (
	eventSessionStarted  = "SESSION_STARTED"
	eventSessionDenied   = "SESSION_DENIED"
	eventActionPerformed = "ACTION_PERFORMED"
	eventActionDenied    = "ACTION_DENIED"
)

// auditClient appends acting events to Nominee Service's audit chain.
//
// The chain lives with the service that owns the delegation record, so the
// authority and its exercise can be read back as one ordered, verifiable
// account rather than correlated across systems afterwards.
type auditClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newAuditClient(cfg config.InternalConfig) *auditClient {
	timeout := cfg.GateTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &auditClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.NomineeServiceURL), "/"),
		apiKey:  strings.TrimSpace(cfg.GateAPIKey),
		http:    &http.Client{Timeout: timeout},
	}
}

type auditEvent struct {
	OwnerID   string `json:"ownerId"`
	NomineeID string `json:"nomineeId"`
	Event     string `json:"event"`
	Detail    string `json:"detail,omitempty"`
}

// record appends one event, and reports whether it was written.
//
// A failure is logged at error level rather than returned to the caller: the
// alternative is refusing an action the owner authorised because a separate
// service is briefly unreachable. That trade is deliberate, and it is why the
// failure is logged loudly enough to be alerted on - an audit trail with silent
// gaps is worse than one known to be incomplete.
func (a *auditClient) record(ctx context.Context, event auditEvent) {
	// A missing audit client must never take down the request path it observes.
	if a == nil || a.baseURL == "" || a.apiKey == "" {
		slog.Error("impersonation: audit not configured, acting event NOT recorded",
			"event", event.Event, "owner", event.OwnerID, "nominee", event.NomineeID)
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		slog.Error("impersonation: could not encode audit event", "event", event.Event, "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.baseURL+"/internal/nominations/audit", bytes.NewReader(body))
	if err != nil {
		slog.Error("impersonation: could not build audit request", "event", event.Event, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", a.apiKey)

	resp, err := a.http.Do(req)
	if err != nil {
		slog.Error("impersonation: acting event NOT recorded", "event", event.Event,
			"owner", event.OwnerID, "nominee", event.NomineeID, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		slog.Error("impersonation: acting event NOT recorded", "event", event.Event,
			"owner", event.OwnerID, "nominee", event.NomineeID,
			"error", fmt.Sprintf("audit endpoint returned HTTP %d", resp.StatusCode))
	}
}

// recordAction appends the outcome of one attempted action. The permission is
// named whether or not it was held, so a refusal records what was reached for.
func (a *auditClient) recordAction(ctx context.Context, owner, nominee, permission, resourceID string, allowed bool, reason string) {
	event := eventActionPerformed
	if !allowed {
		event = eventActionDenied
	}
	detail := "permission=" + permission
	if resourceID != "" {
		detail += " resource=" + resourceID
	}
	if !allowed && reason != "" {
		detail += " reason=" + reason
	}
	a.record(ctx, auditEvent{
		OwnerID:   owner,
		NomineeID: nominee,
		Event:     event,
		Detail:    detail,
	})
}
