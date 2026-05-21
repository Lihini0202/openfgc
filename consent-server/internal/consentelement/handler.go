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

// Package consentelement provides consent element management functionality.
package consentelement

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/wso2/openfgc/internal/consentelement/model"
	"github.com/wso2/openfgc/internal/system/constants"
	"github.com/wso2/openfgc/internal/system/error/serviceerror"
	"github.com/wso2/openfgc/internal/system/utils"
)

// consentElementHandler handles HTTP requests for consent elements.
type consentElementHandler struct {
	service ConsentElementService
}

// newConsentElementHandler creates a new consent element handler.
func newConsentElementHandler(service ConsentElementService) *consentElementHandler {
	return &consentElementHandler{service: service}
}

// createElements handles POST /consent-elements — batch create with partial success (HTTP 200).
func (h *consentElementHandler) createElements(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if err := utils.ValidateOrgID(orgID); err != nil {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	var requests []model.ConsentElementCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		utils.SendError(w, r, serviceerror.CustomServiceError(ErrorInvalidRequestBody, err.Error()))
		return
	}
	if len(requests) == 0 {
		utils.SendError(w, r, &ErrorAtLeastOneElement)
		return
	}

	result, svcErr := h.service.CreateElementsInBatch(r.Context(), requests, orgID)
	if svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	w.Header().Set(constants.HeaderContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// getElement handles GET /consent-elements/{elementId} — returns latest version.
func (h *consentElementHandler) getElement(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if orgID == "" {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	elem, svcErr := h.service.GetElement(r.Context(), r.PathValue("elementId"), orgID)
	if svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	w.Header().Set(constants.HeaderContentType, "application/json")
	json.NewEncoder(w).Encode(elem)
}

// listElements handles GET /consent-elements — list elements with optional filters.
func (h *consentElementHandler) listElements(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if orgID == "" {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	query := r.URL.Query()
	filters := model.ElementListFilters{
		Name:      query.Get("name"),
		Namespace: query.Get("namespace"),
		Type:      query.Get("type"),
		Details:   query.Get("details") == "true",
		Limit:     100,
	}
	if versionStr := query.Get("version"); versionStr != "" {
		// Accept both "v2" and "2" for the query param
		s := strings.TrimPrefix(versionStr, "v")
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			filters.Version = &n
		}
	}
	if limitStr := query.Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 100 {
			filters.Limit = n
		}
	}
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
			filters.Offset = n
		}
	}

	// version filter requires at least name or namespace to narrow results
	if filters.Version != nil && filters.Name == "" && filters.Namespace == "" {
		utils.SendError(w, r, &ErrorVersionRequiresNameOrNamespace)
		return
	}

	result, svcErr := h.service.ListElements(r.Context(), orgID, filters)
	if svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	w.Header().Set(constants.HeaderContentType, "application/json")
	json.NewEncoder(w).Encode(result)
}

// listElementVersions handles GET /consent-elements/{elementId}/versions — all versions.
func (h *consentElementHandler) listElementVersions(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if orgID == "" {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	result, svcErr := h.service.ListElementVersions(r.Context(), r.PathValue("elementId"), orgID)
	if svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	entries := make([]model.ElementVersionItem, len(result.Versions))
	for i, v := range result.Versions {
		entries[i] = model.ElementVersionItem{
			Version:     v.Version,
			DisplayName: v.DisplayName,
			Description: v.Description,
			Schema:      v.Schema,
			Properties:  v.Properties,
			CreatedTime: v.CreatedTime,
		}
	}

	w.Header().Set(constants.HeaderContentType, "application/json")
	json.NewEncoder(w).Encode(model.ElementVersionListResponse{
		ElementID: result.ElementID,
		Name:      result.Name,
		Namespace: result.Namespace,
		Type:      result.Type,
		Versions:  entries,
	})
}

// createElementVersion handles POST /consent-elements/{elementId}/versions — create new version.
func (h *consentElementHandler) createElementVersion(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if err := utils.ValidateOrgID(orgID); err != nil {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	var req model.ElementVersionCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendError(w, r, serviceerror.CustomServiceError(ErrorInvalidRequestBody, err.Error()))
		return
	}

	elem, svcErr := h.service.CreateElementVersion(r.Context(), r.PathValue("elementId"), req, orgID)
	if svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	w.Header().Set(constants.HeaderContentType, "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(elem)
}

// getElementVersion handles GET /consent-elements/{elementId}/versions/{version}.
// version path param must be in vN format (e.g. v1, v2).
func (h *consentElementHandler) getElementVersion(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if orgID == "" {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	version, ok := parseVersionParam(r.PathValue("version"))
	if !ok {
		utils.SendError(w, r, serviceerror.CustomServiceError(ErrorInvalidRequestBody, "version must be in vN format (e.g. v1)"))
		return
	}

	elem, svcErr := h.service.GetElementVersion(r.Context(), r.PathValue("elementId"), version, orgID)
	if svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	w.Header().Set(constants.HeaderContentType, "application/json")
	json.NewEncoder(w).Encode(elem)
}

// deleteElementVersion handles DELETE /consent-elements/{elementId}/versions/{version}.
// version path param must be in vN format (e.g. v1, v2).
func (h *consentElementHandler) deleteElementVersion(w http.ResponseWriter, r *http.Request) {
	orgID := r.Header.Get(constants.HeaderOrgID)
	if orgID == "" {
		utils.SendError(w, r, &ErrorOrgIDRequired)
		return
	}

	version, ok := parseVersionParam(r.PathValue("version"))
	if !ok {
		utils.SendError(w, r, serviceerror.CustomServiceError(ErrorInvalidRequestBody, "version must be in vN format (e.g. v1)"))
		return
	}

	if svcErr := h.service.DeleteElementVersion(r.Context(), r.PathValue("elementId"), version, orgID); svcErr != nil {
		utils.SendError(w, r, svcErr)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseVersionParam parses a vN-format version string (e.g. "v1", "v2") to its integer value.
// Returns (n, true) on success, (0, false) on invalid input.
func parseVersionParam(s string) (int, bool) {
	if !strings.HasPrefix(s, "v") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "v"))
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}
