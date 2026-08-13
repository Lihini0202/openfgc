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

package org.wso2.dpdp.accelerator.portal.webapp.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dpdp.accelerator.portal.webapp.service.OAuthService;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Calls Nominee Service's internal endpoints: the nomination gate that decides
 * what a nominee may do right now, and the audit chain that records what they
 * did.
 *
 * <p>All configuration is explicit — there are no environment fallbacks and no
 * default key — so a missing value fails the gate rather than silently producing
 * a working secret.
 */
public final class NomineeServiceClient {

    private static final Log LOG = LogFactory.getLog(NomineeServiceClient.class);

    /**
     * The nomination gate could not be consulted. Never treated as permission to
     * proceed.
     */
    public static class GateUnavailableException extends Exception {

        private static final long serialVersionUID = 1L;

        public GateUnavailableException(String message, Throwable cause) {

            super(message, cause);
        }

        public GateUnavailableException(String message) {

            super(message);
        }
    }

    /** The gate's answer: whether the nomination is live, and what it grants. */
    public static final class Decision {

        private final boolean active;
        private final List<String> permissions;

        Decision(boolean active, List<String> permissions) {

            this.active = active;
            this.permissions = List.copyOf(permissions);
        }

        public boolean isActive() {

            return active;
        }

        public boolean grants(String permission) {

            return permissions.contains(permission);
        }
    }

    private final PortalConfig config;

    public NomineeServiceClient(PortalConfig config) {

        this.config = config;
    }

    /**
     * Asks the gate what this owner grants this nominee right now.
     *
     * <p>This is the live half of the authorization decision. It is what makes an
     * owner's edit or an administrator's deactivation take effect on the next
     * request rather than at token expiry.
     */
    public Decision permissions(String owner, String nominee) throws GateUnavailableException {

        String baseUrl = config.getNomineeServiceUrl();
        String apiKey = config.getNomineeGateApiKey();
        if (baseUrl.isEmpty() || apiKey.isEmpty()) {
            throw new GateUnavailableException("nomination gate is not configured");
        }

        String endpoint = baseUrl + "/internal/nominations/permissions"
                + "?owner=" + encode(owner) + "&nominee=" + encode(nominee);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(Duration.ofSeconds(config.getNomineeGateTimeoutSeconds()))
                .header(PortalConstants.INTERNAL_KEY_HEADER, apiKey)
                .header("Accept", PortalConstants.CONTENT_TYPE_JSON)
                .GET()
                .build();

        try {
            HttpResponse<String> response = OAuthService.getInstance().httpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GateUnavailableException("gate returned HTTP " + response.statusCode());
            }
            JsonNode body = HttpUtil.mapper().readTree(response.body());
            List<String> permissions = new ArrayList<>();
            for (JsonNode entry : body.path("permissions")) {
                if (entry.isTextual()) {
                    permissions.add(entry.asText());
                }
            }
            return new Decision(body.path("active").asBoolean(false), permissions);
        } catch (IOException e) {
            throw new GateUnavailableException("gate call failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GateUnavailableException("gate call was interrupted", e);
        }
    }

    /**
     * Appends one event to Nominee Service's audit chain.
     *
     * <p>A failure is logged at error level rather than thrown: the alternative
     * is refusing an action the owner authorised because a separate service is
     * briefly unreachable. That trade is deliberate, and it is why the failure is
     * logged loudly enough to alert on — an audit trail with silent gaps is worse
     * than one known to be incomplete.
     */
    public void record(String owner, String nominee, String event, String detail) {

        String baseUrl = config.getNomineeServiceUrl();
        String apiKey = config.getNomineeGateApiKey();
        if (baseUrl.isEmpty() || apiKey.isEmpty()) {
            LOG.error("Audit not configured, acting event NOT recorded: event=" + LogUtil.sanitize(event)
                    + " owner=" + LogUtil.sanitize(owner) + " nominee=" + LogUtil.sanitize(nominee));
            return;
        }

        ObjectNode payload = HttpUtil.mapper().createObjectNode();
        payload.put("ownerId", owner);
        payload.put("nomineeId", nominee);
        payload.put("event", event);
        if (detail != null && !detail.isEmpty()) {
            payload.put("detail", detail);
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/internal/nominations/audit"))
                    .timeout(Duration.ofSeconds(config.getNomineeGateTimeoutSeconds()))
                    .header(PortalConstants.INTERNAL_KEY_HEADER, apiKey)
                    .header("Content-Type", PortalConstants.CONTENT_TYPE_JSON)
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                    .build();
            HttpResponse<String> response = OAuthService.getInstance().httpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                LOG.error("Acting event NOT recorded: event=" + LogUtil.sanitize(event)
                        + " owner=" + LogUtil.sanitize(owner) + " nominee=" + LogUtil.sanitize(nominee)
                        + " status=" + response.statusCode());
            }
        } catch (IOException e) {
            LOG.error("Acting event NOT recorded: event=" + LogUtil.sanitize(event)
                    + " owner=" + LogUtil.sanitize(owner) + " nominee=" + LogUtil.sanitize(nominee), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.error("Acting event NOT recorded (interrupted): event=" + LogUtil.sanitize(event), e);
        }
    }

    /**
     * Records the outcome of one attempted action. The permission is named
     * whether or not it was held, so a refusal records what was reached for.
     */
    public void recordAction(String owner, String nominee, String permission, String resourceId,
                             boolean allowed, String reason) {

        StringBuilder detail = new StringBuilder("permission=").append(permission);
        if (resourceId != null && !resourceId.isEmpty()) {
            detail.append(" resource=").append(resourceId);
        }
        if (!allowed && reason != null && !reason.isEmpty()) {
            detail.append(" reason=").append(reason);
        }
        record(owner, nominee, allowed ? PortalConstants.EVENT_ACTION_PERFORMED
                : PortalConstants.EVENT_ACTION_DENIED, detail.toString());
    }

    private static String encode(String value) {

        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
