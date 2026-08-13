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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import java.text.Normalizer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * A SCIM2 directory client for the Identity Server's user management API, used
 * by the nominee flow to resolve people the signed-in user is not.
 *
 * <p>This deliberately does NOT forward the caller's access token the way
 * {@link IdentityServerClient} does. Resolving another user's record is not
 * something a user's own token is permitted to do, so the client authenticates
 * as its own service identity via the OAuth2 client-credentials grant.
 */
public final class ScimDirectoryClient {

    private static final Log LOG = LogFactory.getLog(ScimDirectoryClient.class);

    /** Thrown when a lookup matches no user. Distinct from an upstream failure. */
    public static class UserNotFoundException extends Exception {

        private static final long serialVersionUID = 1L;

        public UserNotFoundException(String message) {

            super(message);
        }
    }

    /** Thrown when the directory itself could not be consulted. Never means "no". */
    public static class DirectoryUnavailableException extends Exception {

        private static final long serialVersionUID = 1L;

        public DirectoryUnavailableException(String message, Throwable cause) {

            super(message, cause);
        }

        public DirectoryUnavailableException(String message) {

            super(message);
        }
    }

    /** A minimal user record, which is all the nominee flow ever needs. */
    public static final class UserSummary {

        private final String id;
        private final String name;
        private final String email;

        UserSummary(String id, String name, String email) {

            this.id = id;
            this.name = name;
            this.email = email;
        }

        public String getId() {

            return id;
        }

        public String getName() {

            return name;
        }

        public String getEmail() {

            return email;
        }
    }

    // SCIM2 filter operators. Resolving one specific person uses equality;
    // letting somebody look a person up uses containment, since a search box
    // that only matches a complete address is not a search.
    private static final String FILTER_EQUALS = "eq";
    private static final String FILTER_CONTAINS = "co";

    private static volatile ScimDirectoryClient instance;

    private final PortalConfig config;
    private final Object tokenLock = new Object();
    private String cachedToken;
    private Instant tokenExpiry = Instant.EPOCH;

    private ScimDirectoryClient(PortalConfig config) {

        this.config = config;
    }

    public static ScimDirectoryClient getInstance(PortalConfig config) {

        if (instance == null) {
            synchronized (ScimDirectoryClient.class) {
                if (instance == null) {
                    instance = new ScimDirectoryClient(config);
                }
            }
        }
        return instance;
    }

    /**
     * Resolves a user ID to a summary, or reports the user absent.
     */
    public UserSummary getUser(String id) throws UserNotFoundException, DirectoryUnavailableException {

        JsonNode doc = send("/scim2/Users/" + encodePath(id), true);
        if (doc == null) {
            throw new UserNotFoundException("no user with id " + id);
        }
        return toSummary(doc);
    }

    /**
     * Resolves an email to the user who holds it.
     *
     * <p>The SCIM2 filter is applied server-side, but the result is re-checked
     * here: a {@code co}-style backend or a case-folding directory can return
     * near-matches, and a nomination must be aimed at exactly the address the
     * owner typed.
     */
    public UserSummary findByEmail(String email) throws UserNotFoundException, DirectoryUnavailableException {

        String wanted = canonicalEmail(email);
        for (JsonNode doc : findByAttribute("email", FILTER_EQUALS, email)) {
            UserSummary user = toSummary(doc);
            if (user.getEmail() != null && canonicalEmail(user.getEmail()).equals(wanted)) {
                return user;
            }
        }
        throw new UserNotFoundException("no registered user with email " + email);
    }

    /**
     * Searches users by partial email or username, for the admin search box.
     */
    public List<UserSummary> search(String query) throws DirectoryUnavailableException {

        String trimmed = query == null ? "" : query.trim();
        if (trimmed.isEmpty()) {
            return List.of();
        }
        Set<String> seen = new LinkedHashSet<>();
        List<UserSummary> matches = new ArrayList<>();
        for (String attribute : List.of("email", "username")) {
            for (JsonNode doc : findByAttribute(attribute, FILTER_CONTAINS, trimmed)) {
                UserSummary user = toSummary(doc);
                if (user.getId() != null && seen.add(user.getId())) {
                    matches.add(user);
                }
            }
        }
        return matches;
    }

    /**
     * Reports whether a user holds a role, directly or through a group the role
     * is assigned to.
     *
     * <p>Evaluated per request rather than once at sign-in, so revoking an
     * administrator's role takes effect on their next call rather than at token
     * expiry.
     */
    public boolean isUserInRole(String roleName, String userId) throws DirectoryUnavailableException {

        String roleId = findRoleIdByName(roleName);
        if (roleId == null) {
            return false;
        }
        JsonNode role = send("/scim2/v2/Roles/" + encodePath(roleId), true);
        if (role == null) {
            return false;
        }
        for (JsonNode member : role.path("users")) {
            if (userId.equals(member.path("value").asText(null))) {
                return true;
            }
        }
        for (JsonNode group : role.path("groups")) {
            String groupId = group.path("value").asText(null);
            if (groupId != null && groupHasMember(groupId, userId)) {
                return true;
            }
        }
        return false;
    }

    private String findRoleIdByName(String roleName) throws DirectoryUnavailableException {

        String filter = "displayName " + FILTER_EQUALS + " \"" + escapeFilterValue(roleName) + "\"";
        JsonNode page = send("/scim2/v2/Roles?filter=" + encodeQuery(filter), false);
        if (page == null) {
            return null;
        }
        for (JsonNode resource : page.path("Resources")) {
            String id = resource.path("id").asText(null);
            if (id != null) {
                return id;
            }
        }
        return null;
    }

    private boolean groupHasMember(String groupId, String userId) throws DirectoryUnavailableException {

        JsonNode group = send("/scim2/Groups/" + encodePath(groupId), true);
        if (group == null) {
            return false;
        }
        for (JsonNode member : group.path("members")) {
            if (userId.equals(member.path("value").asText(null))) {
                return true;
            }
        }
        return false;
    }

    private List<JsonNode> findByAttribute(String attribute, String op, String value)
            throws DirectoryUnavailableException {

        String filter = filterPathFor(attribute) + " " + op + " \"" + escapeFilterValue(value) + "\"";
        JsonNode page = send("/scim2/Users?filter=" + encodeQuery(filter), false);
        if (page == null) {
            return List.of();
        }
        List<JsonNode> resources = new ArrayList<>();
        page.path("Resources").forEach(resources::add);
        return resources;
    }

    /**
     * Maps a flat attribute name onto its SCIM2 filter path: known core
     * attributes have fixed paths, everything else is schema-qualified under the
     * configured custom extension.
     */
    private String filterPathFor(String attribute) {

        switch (attribute) {
            case "email":
                return "emails";
            case "username":
                return "userName";
            default:
                return config.getScimCustomSchemaUrn() + ":" + attribute;
        }
    }

    /**
     * Flattens a SCIM2 User resource into the summary the portal uses. SCIM2
     * mixes fixed core fields with schema-qualified extensions, so the fields
     * are read individually rather than bound to a type.
     */
    private UserSummary toSummary(JsonNode doc) {

        String id = doc.path("id").asText(null);
        String email = firstEmail(doc);
        return new UserSummary(id, displayName(doc), email);
    }

    private static String firstEmail(JsonNode doc) {

        JsonNode emails = doc.path("emails");
        for (JsonNode entry : emails) {
            if (entry.isTextual()) {
                return entry.asText();
            }
            String value = entry.path("value").asText(null);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    /**
     * Builds a human-readable name, falling back through the same order as the
     * Go BFF so both implementations label a person identically.
     */
    private static String displayName(JsonNode doc) {

        String given = doc.path("name").path("givenName").asText("").trim();
        String family = doc.path("name").path("familyName").asText("").trim();
        if (!given.isEmpty() && !family.isEmpty()) {
            return given + " " + family;
        }
        if (!given.isEmpty()) {
            return given;
        }
        if (!family.isEmpty()) {
            return family;
        }
        String formatted = doc.path("name").path("formatted").asText("").trim();
        if (!formatted.isEmpty()) {
            return formatted;
        }
        return doc.path("userName").asText("").trim();
    }

    /**
     * Issues a SCIM2 request with a service token.
     *
     * @param notFoundIsNull when true a 404 yields null rather than an error,
     *                       for lookups where absence is an ordinary outcome
     */
    private JsonNode send(String path, boolean notFoundIsNull) throws DirectoryUnavailableException {

        String token = serviceToken();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getIdentityServerInternalBaseUrl() + path))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .header("Accept", PortalConstants.CONTENT_TYPE_JSON)
                .GET()
                .build();
        try {
            HttpResponse<String> response = OAuthService.getInstance().httpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404 && notFoundIsNull) {
                return null;
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new DirectoryUnavailableException(
                        "SCIM2 request to " + path + " returned HTTP " + response.statusCode());
            }
            return HttpUtil.mapper().readTree(response.body());
        } catch (IOException e) {
            throw new DirectoryUnavailableException("SCIM2 request to " + path + " failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DirectoryUnavailableException("SCIM2 request to " + path + " was interrupted", e);
        }
    }

    /**
     * Returns a cached client-credentials token, refreshing it shortly before it
     * expires so an in-flight request never races the expiry.
     */
    private String serviceToken() throws DirectoryUnavailableException {

        synchronized (tokenLock) {
            if (cachedToken != null && Instant.now().isBefore(tokenExpiry)) {
                return cachedToken;
            }
            String clientId = config.getScimClientId();
            String clientSecret = config.getScimClientSecret();
            if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
                throw new DirectoryUnavailableException("SCIM2 client credentials are not configured");
            }
            String basicAuth = Base64.getEncoder().encodeToString(
                    (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            // internal_user_mgt_list is required in addition to _view: the
            // Identity Server treats a filtered /scim2/Users query as a list
            // operation and refuses it with 403 on _view alone.
            String form = "grant_type=client_credentials&scope="
                    + encodeQuery("internal_user_mgt_list internal_user_mgt_view "
                            + "internal_role_mgt_view internal_group_mgt_view");
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getIdentityServerInternalBaseUrl() + "/oauth2/token"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Basic " + basicAuth)
                    .header("Content-Type", PortalConstants.CONTENT_TYPE_FORM)
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            try {
                HttpResponse<String> response = OAuthService.getInstance().httpClient()
                        .send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new DirectoryUnavailableException(
                            "client-credentials token request returned HTTP " + response.statusCode());
                }
                JsonNode body = HttpUtil.mapper().readTree(response.body());
                String token = body.path("access_token").asText("");
                if (token.isEmpty()) {
                    throw new DirectoryUnavailableException("client-credentials response carried no access_token");
                }
                long expiresIn = body.path("expires_in").asLong(3600L);
                cachedToken = token;
                // Refresh a minute early rather than at the boundary.
                tokenExpiry = Instant.now().plusSeconds(Math.max(expiresIn - 60L, 30L));
                LOG.debug("Refreshed SCIM2 directory service token");
                return cachedToken;
            } catch (IOException e) {
                throw new DirectoryUnavailableException("client-credentials token request failed", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new DirectoryUnavailableException("client-credentials token request was interrupted", e);
            }
        }
    }

    /**
     * Reduces an address to a single comparable form.
     *
     * <p>The directory's own filter has already selected candidates; this decides
     * whether a candidate is really the address the owner typed. Normalising to
     * NFKC before case folding matters because two different Unicode sequences
     * can render identically — comparing the raw strings would let a visually
     * identical address be treated as a different person, and case folding
     * without a fixed locale would decide that differently depending on the
     * JVM's default locale.
     */
    private static String canonicalEmail(String value) {

        return Normalizer.normalize(value, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    private static String escapeFilterValue(String value) {

        return value.replace("\"", "\\\"");
    }

    private static String encodeQuery(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String encodePath(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
