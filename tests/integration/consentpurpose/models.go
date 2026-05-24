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

package consentpurpose

// =============================================================================
// Request types — what we send to the server.
// These mirror the server's model/consent_purpose.go API request types exactly.
// =============================================================================

// CreatePurposeRequest is the body for POST /consent-purposes.
// The group-id is read from the request header, not this body.
type CreatePurposeRequest struct {
	Name        string             `json:"name"`
	DisplayName *string            `json:"displayName,omitempty"`
	Description *string            `json:"description,omitempty"`
	Properties  map[string]string  `json:"properties,omitempty"`
	Elements    []ElementRefRequest `json:"elements,omitempty"`
}

// CreatePurposeVersionRequest is the body for POST /consent-purposes/{purposeId}/versions.
type CreatePurposeVersionRequest struct {
	DisplayName *string            `json:"displayName,omitempty"`
	Description *string            `json:"description,omitempty"`
	Properties  map[string]string  `json:"properties,omitempty"`
	Elements    []ElementRefRequest `json:"elements,omitempty"`
}

// ElementRefRequest identifies an element within a purpose create or version request body.
type ElementRefRequest struct {
	Name      string  `json:"name"`
	Namespace string  `json:"namespace,omitempty"` // defaults to "default" when absent
	Version   *string `json:"version,omitempty"`   // nil = use latest; "v1", "v2", …
	Mandatory bool    `json:"mandatory"`
}

// =============================================================================
// Response types — what we receive from the server.
// Field names mirror the server's model/consent_purpose.go response types exactly.
// If the server renames a field, unmarshalling will silently zero it — the
// assertions in the test files will catch the drift.
// =============================================================================

// PurposeElementResponse is one element entry within a PurposeResponse or PurposeVersionItem.
type PurposeElementResponse struct {
	ElementID string `json:"elementId"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   string `json:"version"` // "v1", "v2", …
	Mandatory bool   `json:"mandatory"`
}

// PurposeResponse is returned by:
//   - POST   /consent-purposes              (HTTP 201)
//   - GET    /consent-purposes/{purposeId}  (HTTP 200, latest version)
//   - POST   /consent-purposes/{purposeId}/versions        (HTTP 201)
//   - GET    /consent-purposes/{purposeId}/versions/{ver}  (HTTP 200)
type PurposeResponse struct {
	PurposeID   string                   `json:"purposeId"`
	Name        string                   `json:"name"`
	GroupID     string                   `json:"groupId"`
	Version     string                   `json:"version"` // "v1", "v2", …
	DisplayName *string                  `json:"displayName,omitempty"`
	Description *string                  `json:"description,omitempty"`
	Properties  map[string]string        `json:"properties,omitempty"`
	Elements    []PurposeElementResponse `json:"elements,omitempty"`
	CreatedTime int64                    `json:"createdTime"`
}

// PageMetadata carries pagination state in all list responses.
type PageMetadata struct {
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Count  int `json:"count"`
	Limit  int `json:"limit"`
}

// PurposeListResponse is the body returned by GET /consent-purposes.
type PurposeListResponse struct {
	Data     []PurposeResponse `json:"data"`
	Metadata PageMetadata      `json:"metadata"`
}

// PurposeVersionItem is one entry inside PurposeVersionListResponse.Versions.
// Purpose-level fields (Name, GroupID) are hoisted to the parent object.
type PurposeVersionItem struct {
	Version     string                   `json:"version"`
	DisplayName *string                  `json:"displayName,omitempty"`
	Description *string                  `json:"description,omitempty"`
	Properties  map[string]string        `json:"properties,omitempty"`
	Elements    []PurposeElementResponse `json:"elements,omitempty"`
	CreatedTime int64                    `json:"createdTime"`
}

// PurposeVersionListResponse is the body returned by GET /consent-purposes/{purposeId}/versions.
type PurposeVersionListResponse struct {
	PurposeID string               `json:"purposeId"`
	Name      string               `json:"name"`
	GroupID   string               `json:"groupId"`
	Versions  []PurposeVersionItem `json:"versions"`
}

// ErrorResponse is the structured error body the server returns on HTTP 4xx/5xx.
type ErrorResponse struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Description string `json:"description"`
	TraceID     string `json:"traceId"`
}
