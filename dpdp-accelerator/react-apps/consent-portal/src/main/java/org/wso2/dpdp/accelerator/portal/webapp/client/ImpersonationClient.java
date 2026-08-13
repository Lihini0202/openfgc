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
import org.wso2.dpdp.accelerator.portal.webapp.service.OAuthService;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Performs the Identity Server's two-step impersonation token exchange.
 *
 * <p>Whether a nominee may act for a given owner is decided entirely by Nominee
 * Service before this client is invoked; the Identity Server is only asked its
 * own generic question — does this actor hold the impersonation scope.
 */
public final class ImpersonationClient {

    /** The Identity Server has not been configured for impersonation. */
    public static class NotConfiguredException extends Exception {

        private static final long serialVersionUID = 1L;

        public NotConfiguredException(String message) {

            super(message);
        }
    }

    /** Any failure talking to the Identity Server. */
    public static class IdentityServerUnavailableException extends Exception {

        private static final long serialVersionUID = 1L;

        public IdentityServerUnavailableException(String message, Throwable cause) {

            super(message, cause);
        }

        public IdentityServerUnavailableException(String message) {

            super(message);
        }
    }

    /** An impersonation access token carrying {@code sub}=owner, {@code act.sub}=nominee. */
    public static final class Token {

        private final String accessToken;
        private final Instant expiresAt;

        Token(String accessToken, Instant expiresAt) {

            this.accessToken = accessToken;
            this.expiresAt = expiresAt;
        }

        public String getAccessToken() {

            return accessToken;
        }

        public Instant getExpiresAt() {

            return expiresAt;
        }
    }

    private final PortalConfig config;

    public ImpersonationClient(PortalConfig config) {

        this.config = config;
    }

    /**
     * Builds step 1: the authorization-endpoint URL the nominee's browser must be
     * redirected to.
     *
     * <p>This step cannot be performed server-to-server. The Identity Server
     * identifies the impersonator from an interactive session (its commonauth
     * cookie), not from a bearer token, so the request has to originate in the
     * nominee's browser where that cookie lives. The response comes back as a URL
     * fragment, which likewise only the browser can read.
     *
     * <p>The scopes requested are a ceiling <em>request</em>, not a grant: the
     * Identity Server narrows them to what the owner may do, and the nomination
     * validator extension narrows them again to what the owner granted this
     * specific nominee.
     */
    public String authorizeUrl(String ownerId, String state, String nonce, List<String> scopes)
            throws NotConfiguredException {

        String baseUrl = config.getIdentityServerBaseUrl();
        if (baseUrl.isEmpty()) {
            throw new NotConfiguredException("identity server base URL is not configured");
        }
        String redirectUri = config.getImpersonationRedirectUri();
        if (redirectUri.isEmpty()) {
            throw new NotConfiguredException("impersonation redirect URI is not configured");
        }

        List<String> requested = new ArrayList<>();
        requested.add("openid");
        requested.add(config.getImpersonationScope());
        requested.addAll(scopes);

        StringBuilder query = new StringBuilder();
        appendParam(query, "response_type", "id_token subject_token");
        appendParam(query, "client_id", config.getClientId());
        appendParam(query, "redirect_uri", redirectUri);
        appendParam(query, "requested_subject", ownerId);
        appendParam(query, "scope", String.join(" ", dedupe(requested)));
        appendParam(query, "state", state);
        appendParam(query, "nonce", nonce);
        return baseUrl + "/oauth2/authorize?" + query;
    }

    /**
     * Performs step 2: the RFC 8693 exchange that turns a subject token into a
     * usable impersonation access token.
     *
     * <p>{@code actorToken} is the nominee's own access token, and it is
     * mandatory. The Identity Server only treats a request as impersonation when
     * all four of {@code subject_token}, {@code subject_token_type},
     * {@code actor_token} and {@code actor_token_type} are present; omit the
     * actor pair and it silently falls through to the plain federated-exchange
     * path, which then fails with "Invalid Subject Token".
     *
     * <p>It is also the stronger check: the Identity Server compares the actor
     * token's subject against the subject token's {@code may_act} claim, proving
     * the caller really is the nominee named in it rather than merely holding the
     * token.
     *
     * <p>No {@code scope} parameter is sent, deliberately. The Identity Server
     * treats the subject token's scope claim as a ceiling and silently drops any
     * requested scope not present in it; sending nothing makes the resulting
     * token inherit the already-narrowed set verbatim, with no silent filtering
     * to debug.
     */
    public Token exchangeSubjectToken(String subjectToken, String actorToken)
            throws NotConfiguredException, IdentityServerUnavailableException {

        String baseUrl = config.getIdentityServerInternalBaseUrl();
        if (baseUrl.isEmpty()) {
            throw new NotConfiguredException("identity server base URL is not configured");
        }
        if (subjectToken == null || subjectToken.trim().isEmpty()) {
            throw new IdentityServerUnavailableException("empty subject_token");
        }
        if (actorToken == null || actorToken.trim().isEmpty()) {
            throw new IdentityServerUnavailableException("empty actor_token");
        }

        StringBuilder form = new StringBuilder();
        appendParam(form, "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        appendParam(form, "subject_token", subjectToken.trim());
        appendParam(form, "subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
        appendParam(form, "actor_token", actorToken.trim());
        appendParam(form, "actor_token_type", "urn:ietf:params:oauth:token-type:jwt");
        appendParam(form, "requested_token_type", "urn:ietf:params:oauth:token-type:access_token");

        String basicAuth = Base64.getEncoder().encodeToString(
                (config.getClientId() + ":" + config.getClientSecret()).getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth2/token"))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Basic " + basicAuth)
                .header("Content-Type", PortalConstants.CONTENT_TYPE_FORM)
                .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                .build();

        try {
            HttpResponse<String> response = OAuthService.getInstance().httpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IdentityServerUnavailableException(
                        "token exchange returned HTTP " + response.statusCode() + ": " + response.body());
            }
            JsonNode body = HttpUtil.mapper().readTree(response.body());
            String accessToken = body.path("access_token").asText("");
            if (accessToken.isEmpty()) {
                throw new IdentityServerUnavailableException("token exchange returned no access_token");
            }
            long expiresIn = body.path("expires_in").asLong(0L);
            // Zero means the response carried no expiry; the caller falls back to
            // the verified token's own exp claim rather than inventing one.
            Instant expiresAt = expiresIn > 0 ? Instant.now().plusSeconds(expiresIn) : null;
            return new Token(accessToken, expiresAt);
        } catch (IOException e) {
            throw new IdentityServerUnavailableException("token exchange failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdentityServerUnavailableException("token exchange was interrupted", e);
        }
    }

    private static List<String> dedupe(List<String> values) {

        Set<String> seen = new LinkedHashSet<>();
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                seen.add(value.trim());
            }
        }
        return new ArrayList<>(seen);
    }

    private static void appendParam(StringBuilder target, String name, String value) {

        if (target.length() > 0) {
            target.append('&');
        }
        target.append(URLEncoder.encode(name, StandardCharsets.UTF_8))
                .append('=')
                .append(URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8));
    }
}
