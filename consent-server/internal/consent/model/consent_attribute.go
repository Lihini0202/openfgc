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

package model

// =============================================================================
// DB types — store layer only, db tags, no json tags
// =============================================================================

// ConsentAttribute is one row from the CONSENT_ATTRIBUTE table.
type ConsentAttribute struct {
	ConsentID string `db:"CONSENT_ID"`
	AttKey    string `db:"ATT_KEY"`
	AttValue  string `db:"ATT_VALUE"`
	OrgID     string `db:"ORG_ID"`
}

// =============================================================================
// Service input types — handler → service, no tags
// =============================================================================

// ConsentAttributeCreateInput holds the key-value map to persist for a given consent.
type ConsentAttributeCreateInput struct {
	ConsentID  string
	Attributes map[string]string
}

// ConsentAttributeSearchInput holds the query parameters for the attribute search endpoint.
// Key is required; Value is optional — when empty only the key is matched.
type ConsentAttributeSearchInput struct {
	Key   string
	Value string // empty = match by key only
	OrgID string
}

// =============================================================================
// Service return types — service → handler, no tags
// =============================================================================

// ConsentAttributeOutput is the service-layer representation of one consent's attributes.
type ConsentAttributeOutput struct {
	ConsentID  string
	Attributes map[string]string
	OrgID      string
}
