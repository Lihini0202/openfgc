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

import org.wso2.dpdp.accelerator.portal.webapp.service.OAuthService;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

/**
 * Calls the Consent Server, the service that owns consent records.
 *
 * <p>The tenant is taken from the verified mask token rather than from anything
 * the caller sent: the Consent Server is multi-tenant on the {@code org-id}
 * header, so a client-supplied value would let a nominee reach across tenants.
 */
public final class ConsentServerClient {

    /** Base path of the Consent Server's consent API. */
    public static final String CONSENTS_API = "/api/v1/consents";

    /** The Consent Server could not be reached, or answered unusably. */
    public static class UpstreamUnavailableException extends Exception {

        private static final long serialVersionUID = 1L;

        public UpstreamUnavailableException(String message, Throwable cause) {

            super(message, cause);
        }

        public UpstreamUnavailableException(String message) {

            super(message);
        }
    }

    /** A raw upstream response, relayed to the SPA after translation. */
    public static final class Result {

        private final int status;
        private final String body;

        Result(int status, String body) {

            this.status = status;
            this.body = body;
        }

        public int getStatus() {

            return status;
        }

        public String getBody() {

            return body;
        }

        public boolean isSuccess() {

            return status >= 200 && status < 300;
        }
    }

    private final PortalConfig config;
    private final String organizationId;

    public ConsentServerClient(PortalConfig config, String organizationId) {

        this.config = config;
        this.organizationId = organizationId;
    }

    public Result get(String path) throws UpstreamUnavailableException {

        return send(builder(path, null).GET().build());
    }

    public Result put(String path, String jsonBody, String trustedGroupId)
            throws UpstreamUnavailableException {

        return send(builder(path, trustedGroupId)
                .header("Content-Type", PortalConstants.CONTENT_TYPE_JSON)
                .PUT(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build());
    }

    public Result post(String path, String jsonBody, String trustedGroupId)
            throws UpstreamUnavailableException {

        HttpRequest.Builder builder = builder(path, trustedGroupId);
        if (jsonBody == null) {
            builder.POST(HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", PortalConstants.CONTENT_TYPE_JSON)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        }
        return send(builder.build());
    }

    /** Relays an arbitrary allowlisted method, for the catalog passthrough. */
    public Result relay(String method, String path, String jsonBody) throws UpstreamUnavailableException {

        HttpRequest.Builder builder = builder(path, null);
        if (jsonBody == null || jsonBody.isEmpty()) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", PortalConstants.CONTENT_TYPE_JSON)
                    .method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
        }
        return send(builder.build());
    }

    /**
     * @param trustedGroupId the consent's own group, read from the record the
     *                       server returned rather than from the caller
     */
    private HttpRequest.Builder builder(String path, String trustedGroupId)
            throws UpstreamUnavailableException {

        String baseUrl = config.getConsentServerUrl();
        if (baseUrl.isEmpty()) {
            throw new UpstreamUnavailableException("consent server URL is not configured");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(30))
                .header("Accept", PortalConstants.CONTENT_TYPE_JSON)
                // Correlates one acting action across the portal, the Consent
                // Server and the audit chain.
                .header("X-Correlation-ID", UUID.randomUUID().toString());
        if (organizationId != null && !organizationId.isEmpty()) {
            builder.header("org-id", organizationId);
        }
        // The consent's group, never a client-supplied value: writes are
        // authorised against it, so it is only ever taken from the record the
        // Consent Server itself returned.
        String groupId = trustedGroupId != null && !trustedGroupId.isEmpty()
                ? trustedGroupId : config.getConsentServerPlaceholderClientId();
        if (!groupId.isEmpty()) {
            builder.header("group-id", groupId);
        }
        return builder;
    }

    private Result send(HttpRequest request) throws UpstreamUnavailableException {

        try {
            HttpResponse<String> response = OAuthService.getInstance().httpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());
            return new Result(response.statusCode(), response.body());
        } catch (IOException e) {
            throw new UpstreamUnavailableException("consent server request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UpstreamUnavailableException("consent server request was interrupted", e);
        }
    }
}
