/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.dpdp.accelerator.portal.webapp.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.wso2.dpdp.accelerator.portal.webapp.client.ConsentServerClient;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.TextUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.TextUtil;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds the consent update payload for an approval performed on an owner's
 * behalf.
 *
 * <p>Not final: {@link #fetchPurposePage} is the single call this class makes
 * out to the Consent Server, and it is left open so the payload rules - which
 * are otherwise pure transformations - can be exercised on their own.
 *
 * <p>Approving for an owner must produce exactly the same request as the owner
 * approving for themselves, so the shape of the payload here deliberately
 * mirrors the first-party path field for field. Anything the update payload does
 * not name is dropped rather than passed through, so an approval never carries
 * unreviewed fields back upstream.
 */
public class ConsentApprovalBuilder {

    /** The caller named a purpose/element pair the consent does not offer. */
    public static class InvalidSelectionException extends Exception {

        private static final long serialVersionUID = 1L;

        public InvalidSelectionException(String message) {

            super(message);
        }
    }

    /** The serialized update, plus the group it must be sent under. */
    public static final class Payload {

        private final String body;
        private final String groupId;

        Payload(String body, String groupId) {

            this.body = body;
            this.groupId = groupId;
        }

        public String getBody() {

            return body;
        }

        public String getGroupId() {

            return groupId;
        }
    }

    private final ConsentServerClient client;

    public ConsentApprovalBuilder(ConsentServerClient client) {

        this.client = client;
    }

    /**
     * Rebuilds the consent with the caller's selections applied.
     *
     * @param consentBody   the consent as the Consent Server currently holds it
     * @param selectionBody the caller's chosen optional elements
     * @param ownerId       the user the approval is recorded against
     */
    public Payload build(String consentBody, String selectionBody, String ownerId)
            throws InvalidSelectionException, ConsentServerClient.UpstreamUnavailableException {

        JsonNode consent;
        try {
            consent = HttpUtil.mapper().readTree(consentBody);
        } catch (IOException e) {
            throw new ConsentServerClient.UpstreamUnavailableException("consent server returned unusable JSON", e);
        }

        Set<String> selected = parseSelections(selectionBody);
        String groupId = consent.path("groupId").asText("");

        // Which elements are mandatory is not carried on the consent itself, so
        // it is read from the purpose catalog. A mandatory element is approved
        // regardless of what the caller selected.
        Map<String, Map<String, Boolean>> mandatoryByPurpose =
                mandatoryFlags(consent.path("purposes"), consent.path("clientId").asText(""));

        Set<String> matched = new HashSet<>();
        ArrayNode purposes = HttpUtil.mapper().createArrayNode();
        for (JsonNode purpose : consent.path("purposes")) {
            String purposeName = purpose.path("name").asText("");
            Map<String, Boolean> mandatory = mandatoryByPurpose.get(purposeName);
            if (mandatory == null) {
                throw new ConsentServerClient.UpstreamUnavailableException(
                        "no catalog metadata for purpose " + purposeName);
            }

            ObjectNode updatedPurpose = HttpUtil.mapper().createObjectNode();
            updatedPurpose.put("name", purposeName);
            copyIfPresent(purpose, updatedPurpose, "description");

            ArrayNode elements = HttpUtil.mapper().createArrayNode();
            for (JsonNode element : purpose.path("elements")) {
                String elementName = element.path("name").asText("");
                Boolean isMandatory = mandatory.get(elementName);
                if (isMandatory == null) {
                    throw new ConsentServerClient.UpstreamUnavailableException(
                            "no catalog metadata for element " + elementName);
                }

                ObjectNode updatedElement = HttpUtil.mapper().createObjectNode();
                updatedElement.put("name", elementName);
                boolean approved;
                if (isMandatory) {
                    approved = true;
                } else {
                    String key = approvalKey(purposeName, elementName);
                    approved = selected.contains(key);
                    if (approved) {
                        matched.add(key);
                    }
                }
                updatedElement.put("isUserApproved", approved);
                copyIfPresent(element, updatedElement, "value");
                updatedElement.put("isMandatory", isMandatory);
                copyIfPresent(element, updatedElement, "type");
                copyIfPresent(element, updatedElement, "description");
                copyIfPresent(element, updatedElement, "properties");
                elements.add(updatedElement);
            }
            updatedPurpose.set("elements", elements);
            purposes.add(updatedPurpose);
        }

        // Every selection must have landed somewhere. A selection naming a
        // purpose or element this consent does not offer is a malformed request,
        // not something to silently ignore.
        if (matched.size() != selected.size()) {
            throw new InvalidSelectionException("selection does not match the consent");
        }

        ObjectNode payload = HttpUtil.mapper().createObjectNode();
        payload.put("type", consent.path("type").asText(""));
        copyIfPresent(consent, payload, "validityTime");
        copyIfPresent(consent, payload, "recurringIndicator");
        copyIfPresent(consent, payload, "dataAccessValidityDuration");
        copyIfPresent(consent, payload, "frequency");
        payload.set("purposes", purposes);
        copyIfPresent(consent, payload, "attributes");
        payload.set("authorizations", authorizations(consent.path("authorizations"), ownerId));

        return new Payload(payload.toString(), groupId);
    }

    /** The consent is not in a state where it can be rejected. */
    public static class InvalidConsentStateException extends Exception {

        private static final long serialVersionUID = 1L;

        public InvalidConsentStateException(String message) {

            super(message);
        }
    }

    /**
     * Builds the update that records this user rejecting a consent.
     *
     * <p>Only the caller's own authorization changes; everybody else's is
     * carried across untouched. Rejecting is confined to a consent still in
     * CREATED - anything already decided is not re-decidable through this path,
     * and a caller who holds no authorization on the consent has nothing to
     * reject.
     */
    public Payload buildRejection(String consentBody, String userId)
            throws InvalidConsentStateException, ConsentServerClient.UpstreamUnavailableException {

        JsonNode consent;
        try {
            consent = HttpUtil.mapper().readTree(consentBody);
        } catch (IOException e) {
            throw new ConsentServerClient.UpstreamUnavailableException("consent server returned unusable JSON", e);
        }
        if (!TextUtil.equalsFolded(consent.path("status").asText("").trim(), "CREATED")) {
            throw new InvalidConsentStateException("only a pending consent can be rejected");
        }

        String wanted = userId.trim();
        boolean found = false;
        ArrayNode authorizations = HttpUtil.mapper().createArrayNode();
        for (JsonNode authorization : consent.path("authorizations")) {
            ObjectNode entry = HttpUtil.mapper().createObjectNode();
            copyIfPresent(authorization, entry, "userId");
            entry.put("type", authorization.path("type").asText(""));
            boolean mine = TextUtil.equalsFolded(authorization.path("userId").asText("").trim(), wanted);
            entry.put("status", mine ? "REJECTED" : authorization.path("status").asText(""));
            JsonNode resources = authorization.path("resources");
            entry.set("resources", resources.isMissingNode() || resources.isNull()
                    ? HttpUtil.mapper().createObjectNode() : resources);
            authorizations.add(entry);
            found = found || mine;
        }
        if (!found) {
            throw new InvalidConsentStateException("caller holds no authorization on this consent");
        }

        ObjectNode payload = HttpUtil.mapper().createObjectNode();
        payload.set("authorizations", authorizations);
        return new Payload(payload.toString(), consent.path("groupId").asText(""));
    }

    /**
     * Rebuilds the authorization list with the owner's entry set to APPROVED,
     * replacing their existing entry when they already hold one.
     */
    private static ArrayNode authorizations(JsonNode existing, String ownerId) {

        ArrayNode out = HttpUtil.mapper().createArrayNode();
        int ownerIndex = -1;
        int index = 0;
        for (JsonNode authorization : existing) {
            ObjectNode entry = HttpUtil.mapper().createObjectNode();
            copyIfPresent(authorization, entry, "userId");
            entry.put("type", authorization.path("type").asText(""));
            entry.put("status", authorization.path("status").asText(""));
            JsonNode resources = authorization.path("resources");
            entry.set("resources", resources.isMissingNode() || resources.isNull()
                    ? HttpUtil.mapper().createObjectNode() : resources);
            out.add(entry);

            String userId = authorization.path("userId").asText("").trim();
            if (ownerIndex < 0 && TextUtil.equalsFolded(userId, ownerId.trim())) {
                ownerIndex = index;
            }
            index++;
        }

        ObjectNode approved = HttpUtil.mapper().createObjectNode();
        approved.put("userId", ownerId);
        approved.put("type", "authorisation");
        approved.put("status", "APPROVED");
        approved.set("resources", HttpUtil.mapper().createObjectNode());
        if (ownerIndex >= 0) {
            out.set(ownerIndex, approved);
        } else {
            out.add(approved);
        }
        return out;
    }

    /**
     * Reads the elements the caller chose to approve.
     *
     * <p>An empty body means "approve nothing optional", which is a legitimate
     * choice; a malformed entry is not.
     */
    private static Set<String> parseSelections(String body) throws InvalidSelectionException {

        Set<String> selected = new LinkedHashSet<>();
        if (body == null || body.trim().isEmpty()) {
            return selected;
        }
        JsonNode selections;
        try {
            selections = HttpUtil.mapper().readTree(body);
        } catch (IOException e) {
            throw new InvalidSelectionException("selections are not valid JSON");
        }
        if (!selections.isArray()) {
            throw new InvalidSelectionException("selections must be an array");
        }
        for (JsonNode selection : selections) {
            String purposeName = selection.path("purposeName").asText("").trim();
            String elementName = selection.path("elementName").asText("").trim();
            if (purposeName.isEmpty() || elementName.isEmpty()) {
                throw new InvalidSelectionException("selection is missing a purpose or element name");
            }
            selected.add(approvalKey(purposeName, elementName));
        }
        return selected;
    }

    /**
     * Resolves, for each purpose on the consent, which of its elements the
     * catalog marks mandatory.
     */
    private Map<String, Map<String, Boolean>> mandatoryFlags(JsonNode purposes, String clientId)
            throws ConsentServerClient.UpstreamUnavailableException {

        Map<String, Map<String, Boolean>> byPurpose = new LinkedHashMap<>();
        for (JsonNode purpose : purposes) {
            String purposeName = purpose.path("name").asText("");
            if (byPurpose.containsKey(purposeName)) {
                continue;
            }
            Set<String> elementNames = new LinkedHashSet<>();
            for (JsonNode element : purpose.path("elements")) {
                elementNames.add(element.path("name").asText(""));
            }

            // Prefer the catalog entry registered to this consent's client; fall
            // back to a name-only lookup, since a purpose may be defined once and
            // shared across clients.
            JsonNode candidate = selectCandidate(fetchPurposePage(purposeName, clientId),
                    purposeName, clientId, elementNames);
            if (candidate == null) {
                candidate = selectCandidate(fetchPurposePage(purposeName, ""),
                        purposeName, clientId, elementNames);
            }
            if (candidate == null) {
                throw new ConsentServerClient.UpstreamUnavailableException(
                        "purpose catalog has no entry for " + purposeName);
            }

            Map<String, Boolean> mandatory = new LinkedHashMap<>();
            for (JsonNode element : candidate.path("elements")) {
                mandatory.put(element.path("name").asText(""), element.path("isMandatory").asBoolean(false));
            }
            byPurpose.put(purposeName, mandatory);
        }
        return byPurpose;
    }

    /**
     * Reads one page of the purpose catalog.
     *
     * <p>Overridable so the payload rules above can be exercised without a
     * Consent Server: everything else in this class is a pure transformation,
     * and this is its only call out.
     */
    protected List<JsonNode> fetchPurposePage(String purposeName, String clientId)
            throws ConsentServerClient.UpstreamUnavailableException {

        StringBuilder query = new StringBuilder("/api/v1/consent-purposes?name=")
                .append(URLEncoder.encode(purposeName, StandardCharsets.UTF_8));
        if (!clientId.isEmpty()) {
            query.append("&clientIds=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
        }
        query.append("&limit=50&offset=0");

        ConsentServerClient.Result result = client.get(query.toString());
        if (result.getStatus() != 200) {
            throw new ConsentServerClient.UpstreamUnavailableException(
                    "purpose catalog returned HTTP " + result.getStatus());
        }
        try {
            List<JsonNode> data = new ArrayList<>();
            HttpUtil.mapper().readTree(result.getBody()).path("data").forEach(data::add);
            return data;
        } catch (IOException e) {
            throw new ConsentServerClient.UpstreamUnavailableException(
                    "purpose catalog returned unusable JSON", e);
        }
    }

    /**
     * Picks the catalog entry that best describes a purpose: one carrying every
     * element the consent uses, preferring the entry registered to this client.
     */
    private static JsonNode selectCandidate(List<JsonNode> candidates, String purposeName,
                                            String clientId, Set<String> requiredElements) {

        List<JsonNode> matchingName = new ArrayList<>();
        for (JsonNode candidate : candidates) {
            if (purposeName.equals(candidate.path("name").asText(null))) {
                matchingName.add(candidate);
            }
        }
        if (matchingName.isEmpty()) {
            return null;
        }

        List<JsonNode> best = new ArrayList<>();
        for (JsonNode candidate : matchingName) {
            Set<String> offered = new HashSet<>();
            for (JsonNode element : candidate.path("elements")) {
                offered.add(element.path("name").asText(""));
            }
            if (offered.containsAll(requiredElements)) {
                best.add(candidate);
            }
        }
        if (best.isEmpty()) {
            best = matchingName;
        }
        if (!clientId.isEmpty()) {
            for (JsonNode candidate : best) {
                if (clientId.equals(candidate.path("clientId").asText(null))) {
                    return candidate;
                }
            }
        }
        return best.get(0);
    }

    private static void copyIfPresent(JsonNode source, ObjectNode target, String field) {

        JsonNode value = source.path(field);
        if (!value.isMissingNode() && !value.isNull()) {
            target.set(field, value);
        }
    }

    private static String approvalKey(String purposeName, String elementName) {

        // Matched case-sensitively on the exact names: these are catalog
        // identifiers, and folding case would let a selection approve an
        // element the caller did not actually name.
        return purposeName + "::" + elementName;
    }
}
