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

// Package model provides data models for consent elements.
package model

import "encoding/json"

// Element type constants — matches the API type values.
const (
	ElementTypeBasic = "basic"
	ElementTypeJSON  = "json"
	ElementTypeXML   = "xml"
)

const DefaultNamespace = "default"

// =============================================================================
// DB types — store layer only, db tags, no json tags
// =============================================================================

// ElementVersion is one row from the ELEMENT table.
// Properties is populated separately from the ELEMENT_PROPERTY table.
type ElementVersion struct {
	VersionID   string            `db:"VERSION_ID"`
	ID          string            `db:"ID"`
	Name        string            `db:"NAME"`
	Namespace   string            `db:"NAMESPACE"`
	Type        string            `db:"TYPE"`
	VersionNum  int               `db:"VERSION"`
	DisplayName *string           `db:"DISPLAY_NAME"`
	Description *string           `db:"DESCRIPTION"`
	Schema      *string           `db:"ELEMENT_SCHEMA"`
	CreatedTime int64             `db:"CREATED_TIME"`
	OrgID       string            `db:"ORG_ID"`
	Properties  map[string]string `db:"-"`
}

// ElementVersionProperty is one row from the ELEMENT_PROPERTY table.
type ElementVersionProperty struct {
	ElementVersionID string `db:"ELEMENT_VERSION_ID"`
	Key              string `db:"ATT_KEY"`
	Value            string `db:"ATT_VALUE"`
	OrgID            string `db:"ORG_ID"`
}

// =============================================================================
// Service input types — handler → service, no tags
// =============================================================================

// CreateElementInput is the input to the CreateElements service method.
type CreateElementInput struct {
	Name        string
	Namespace   string
	DisplayName *string
	Description *string
	Type        string
	Schema      *string
	Properties  map[string]string
}

// CreateElementVersionInput is the input to the CreateElementVersion service method.
type CreateElementVersionInput struct {
	DisplayName *string
	Description *string
	Schema      *string
	Properties  map[string]string
}

// ElementListFilter holds query parameters for the ListElements service method.
type ElementListFilter struct {
	Name      string
	Namespace string
	Type      string
	Version   *int
	Details   bool
	Limit     int
	Offset    int
}

// =============================================================================
// Service return types — service → handler, no tags
// =============================================================================

// CreateElementOutput is the output for one element in a batch create operation.
type CreateElementOutput struct {
	Status  string // "SUCCESS" or "FAILED"
	Element *ElementVersion
	Error   *string
}

// BatchCreateOutput is the return type from CreateElementsInBatch.
type BatchCreateOutput struct {
	Results []CreateElementOutput
}

// ElementListOutput is the return type from ListElements.
type ElementListOutput struct {
	Data   []ElementVersion
	Total  int
	Offset int
	Count  int
	Limit  int
}

// ElementVersionListOutput is the return type from ListElementVersions.
// Common element fields are hoisted to the top level; Versions contains version-specific rows.
type ElementVersionListOutput struct {
	ElementID string
	Name      string
	Namespace string
	Type      string
	Versions  []ElementVersion
}

// =============================================================================
// API request types — HTTP boundary, handler only, json tags, no db tags
// =============================================================================

// CreateElementRequest is one item in the POST /consent-elements batch request body.
// Schema accepts either a JSON object ({"type":"object"}) or a plain string value.
type CreateElementRequest struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Type        string            `json:"type"`
	Schema      json.RawMessage   `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// CreateElementVersionRequest is the body for POST /consent-elements/{elementId}/versions.
// Schema accepts either a JSON object or a plain string value.
type CreateElementVersionRequest struct {
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Schema      json.RawMessage   `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// =============================================================================
// API response types — HTTP boundary, handler only, json tags, no db tags
// =============================================================================

// ElementResponse is the response body for GET /consent-elements/{elementId} and
// GET /consent-elements/{elementId}/versions/{version}.
// Also used as the item type in ElementListResponse; schema and properties are
// omitted when the request did not include details=true.
type ElementResponse struct {
	ElementID   string            `json:"elementId"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Type        string            `json:"type"`
	Version     string            `json:"version"`
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Schema      *string           `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	CreatedTime int64             `json:"createdTime"`
}

// PageMetadata holds pagination metadata for list responses.
type PageMetadata struct {
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Count  int `json:"count"`
	Limit  int `json:"limit"`
}

// ElementListResponse is the response body for GET /consent-elements.
type ElementListResponse struct {
	Data     []ElementResponse `json:"data"`
	Metadata PageMetadata      `json:"metadata"`
}

// BatchResultItem is one entry in BatchCreateResponse.Results.
type BatchResultItem struct {
	Status  string           `json:"status"` // "SUCCESS" or "FAILED"
	Element *ElementResponse `json:"element,omitempty"`
	Error   *string          `json:"error,omitempty"`
}

// BatchCreateResponse is the response body for POST /consent-elements.
type BatchCreateResponse struct {
	Results []BatchResultItem `json:"results"`
}

// ElementVersionItem is one version entry in ElementVersionListResponse.
// Element-level fields (Name, Namespace, Type) are hoisted to the parent object.
type ElementVersionItem struct {
	Version     string            `json:"version"`
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Schema      *string           `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	CreatedTime int64             `json:"createdTime"`
}

// ElementVersionListResponse is the response body for GET /consent-elements/{elementId}/versions.
type ElementVersionListResponse struct {
	ElementID string               `json:"elementId"`
	Name      string               `json:"name"`
	Namespace string               `json:"namespace"`
	Type      string               `json:"type"`
	Versions  []ElementVersionItem `json:"versions"`
}
