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

// ElementVersion represents one version of a consent element — one row in the ELEMENT table.
// All versions sharing the same ID belong to the same logical element.
// VersionNum is the internal integer (1, 2, 3…); Version is the API-facing string ("v1", "v2", "v3"…).
type ElementVersion struct {
	VersionID   string            `json:"-" db:"VERSION_ID"`
	ID          string            `json:"elementId" db:"ID"`
	Name        string            `json:"name" db:"NAME"`
	Namespace   string            `json:"namespace" db:"NAMESPACE"`
	Type        string            `json:"type" db:"TYPE"`
	VersionNum  int               `json:"-" db:"VERSION"`
	Version     string            `json:"version" db:"-"`
	DisplayName *string           `json:"displayName,omitempty" db:"DISPLAY_NAME"`
	Description *string           `json:"description,omitempty" db:"DESCRIPTION"`
	Schema      *string           `json:"schema,omitempty" db:"ELEMENT_SCHEMA"`
	CreatedTime int64             `json:"createdTime" db:"CREATED_TIME"`
	OrgID       string            `json:"-" db:"ORG_ID"`
	Properties  map[string]string `json:"properties,omitempty" db:"-"`
}

// ElementVersionProperty is one row in the ELEMENT_PROPERTY table.
type ElementVersionProperty struct {
	ElementVersionID string `db:"ELEMENT_VERSION_ID"`
	Key              string `db:"ATT_KEY"`
	Value            string `db:"ATT_VALUE"`
	OrgID            string `db:"ORG_ID"`
}

// ElementListFilters holds query parameters for GET /consent-elements.
type ElementListFilters struct {
	Name      string
	Namespace string
	Type      string
	Version   *int
	Details   bool // when true, populate Schema and Properties
	Limit     int
	Offset    int
}

// ConsentElementCreateRequest is one item in the POST /consent-elements batch request body.
// Schema accepts either a JSON object ({"type":"object"}) or a plain string value.
type ConsentElementCreateRequest struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Type        string            `json:"type"`
	Schema      json.RawMessage   `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// ElementVersionCreateRequest is the body for POST /consent-elements/{elementId}/versions.
// Schema accepts either a JSON object or a plain string value.
type ElementVersionCreateRequest struct {
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Schema      json.RawMessage   `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// BulkCreateResultItem is one entry in the BulkCreateResponse.Results slice.
type BulkCreateResultItem struct {
	Status  string          `json:"status"` // "SUCCESS" or "FAILED"
	Element *ElementVersion `json:"element,omitempty"`
	Error   *string         `json:"error,omitempty"`
}

// BulkCreateResponse is the response body for POST /consent-elements (HTTP 200).
type BulkCreateResponse struct {
	Results []BulkCreateResultItem `json:"results"`
}

// ListMetadata holds pagination metadata for list responses.
type ListMetadata struct {
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Count  int `json:"count"`
	Limit  int `json:"limit"`
}

// ListResponse is the response body for GET /consent-elements.
type ListResponse struct {
	Data     []ElementVersion `json:"data"`
	Metadata ListMetadata     `json:"metadata"`
}

// VersionListResponse is the service return type for ListElementVersions.
// Common element fields (Name, Namespace, Type) are hoisted to the top level; only
// version-specific fields appear in each Versions entry.
type VersionListResponse struct {
	ElementID string           `json:"elementId"`
	Name      string           `json:"name"`
	Namespace string           `json:"namespace"`
	Type      string           `json:"type"`
	Versions  []ElementVersion `json:"versions"`
}

// ElementVersionItem is one entry in the ElementVersionListResponse returned by the API.
// Element-level fields (Name, Namespace, Type) are hoisted to the parent object.
type ElementVersionItem struct {
	Version     string            `json:"version"`
	DisplayName *string           `json:"displayName,omitempty"`
	Description *string           `json:"description,omitempty"`
	Schema      *string           `json:"schema,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	CreatedTime int64             `json:"createdTime"`
}

// ElementVersionListResponse is the HTTP response body for GET /consent-elements/{elementId}/versions.
type ElementVersionListResponse struct {
	ElementID string               `json:"elementId"`
	Name      string               `json:"name"`
	Namespace string               `json:"namespace"`
	Type      string               `json:"type"`
	Versions  []ElementVersionItem `json:"versions"`
}
