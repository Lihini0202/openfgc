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

package org.wso2.dpdp.accelerator.portal.webapp.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import javax.servlet.ServletContext;

/**
 * Portal configuration resolved from an optional override file
 * ({@code <IS_HOME>/repository/conf/dpdp-portal.properties}) with webapp
 * context-param defaults as the fallback.
 */
public final class PortalConfig {

    private static final Log LOG = LogFactory.getLog(PortalConfig.class);
    private static final String OVERRIDE_FILE = "dpdp-portal.properties";
    private static volatile PortalConfig instance;

    private final Properties overrides = new Properties();
    private final ServletContext servletContext;

    public static final String IDENTITY_SERVER_BASE_URL = "identity.server.base.url";
    public static final String IDENTITY_SERVER_INTERNAL_BASE_URL = "identity.server.internal.base.url";
    public static final String OAUTH_CLIENT_ID = "oauth.client.id";
    public static final String OAUTH_CLIENT_SECRET = "oauth.client.secret";
    public static final String OAUTH_SCOPES = "oauth.scopes";
    public static final String COOKIE_SECURE = "cookie.secure";

    // Nominee delegation (DPDP nominee feature). All of these are unset by
    // default: a deployment that has not configured the nominee feature must
    // leave the acting routes closed rather than half-working.
    public static final String NOMINEE_SERVICE_URL = "nominee.service.url";
    public static final String NOMINEE_GATE_API_KEY = "nominee.gate.api.key";
    public static final String NOMINEE_GATE_TIMEOUT_SECONDS = "nominee.gate.timeout.seconds";
    public static final String SCIM_CLIENT_ID = "scim.client.id";
    public static final String SCIM_CLIENT_SECRET = "scim.client.secret";
    public static final String SCIM_CUSTOM_SCHEMA_URN = "scim.custom.schema.urn";
    public static final String ADMIN_ROLE_NAME = "admin.role.name";
    public static final String IMPERSONATION_SCOPE = "impersonation.scope";
    public static final String IMPERSONATION_REDIRECT_URI = "impersonation.redirect.uri";
    public static final String MASK_AUDIENCE = "mask.audience";
    public static final String SCOPE_PREFIX = "scope.prefix";
    public static final String EXPECTED_ISSUER = "expected.issuer";
    public static final String CONSENT_SERVER_URL = "consent.server.url";
    public static final String CONSENT_SERVER_PLACEHOLDER_CLIENT_ID = "consent.server.placeholder.client.id";

    private PortalConfig(ServletContext servletContext) {

        this.servletContext = servletContext;
        String carbonHome = System.getProperty("carbon.home");
        if (carbonHome != null) {
            Path overridePath = Paths.get(carbonHome, "repository", "conf", OVERRIDE_FILE);
            if (Files.isReadable(overridePath)) {
                try (InputStream in = Files.newInputStream(overridePath)) {
                    overrides.load(in);
                    LOG.info("Loaded portal configuration overrides from " + overridePath);
                } catch (IOException e) {
                    LOG.warn("Failed to load portal configuration overrides from " + overridePath, e);
                }
            }
        }
    }

    public static PortalConfig getInstance(ServletContext servletContext) {

        if (instance == null) {
            synchronized (PortalConfig.class) {
                if (instance == null) {
                    instance = new PortalConfig(servletContext);
                }
            }
        }
        return instance;
    }

    public String get(String key) {

        String value = overrides.getProperty(key);
        if (value == null || value.isEmpty()) {
            value = servletContext.getInitParameter(key);
        }
        return value;
    }

    public String get(String key, String defaultValue) {

        String value = get(key);
        return (value == null || value.isEmpty()) ? defaultValue : value;
    }

    public String getIdentityServerBaseUrl() {

        return trimTrailingSlash(get(IDENTITY_SERVER_BASE_URL, "https://localhost:9443"));
    }

    public String getIdentityServerInternalBaseUrl() {

        return trimTrailingSlash(get(IDENTITY_SERVER_INTERNAL_BASE_URL, getIdentityServerBaseUrl()));
    }

    public String getClientId() {

        return get(OAUTH_CLIENT_ID);
    }

    public String getClientSecret() {

        return get(OAUTH_CLIENT_SECRET);
    }

    public String getScopes() {

        return get(OAUTH_SCOPES, "openid internal_login");
    }

    public boolean isCookieSecure() {

        return Boolean.parseBoolean(get(COOKIE_SECURE, "true"));
    }

    public String getPortalBasePath() {

        return servletContext.getContextPath();
    }

    public String getNomineeServiceUrl() {

        String value = get(NOMINEE_SERVICE_URL);
        return value == null ? "" : trimTrailingSlash(value.trim());
    }

    public String getNomineeGateApiKey() {

        String value = get(NOMINEE_GATE_API_KEY);
        return value == null ? "" : value.trim();
    }

    public int getNomineeGateTimeoutSeconds() {

        try {
            int seconds = Integer.parseInt(get(NOMINEE_GATE_TIMEOUT_SECONDS, "3").trim());
            return seconds > 0 ? seconds : 3;
        } catch (NumberFormatException e) {
            return 3;
        }
    }

    /**
     * Credentials for the SCIM2 directory client. This is a service identity
     * distinct from the signed-in user: resolving another user's record is not
     * something the caller's own token is permitted to do. Falls back to the
     * portal's OAuth client when a deployment uses one application for both.
     */
    public String getScimClientId() {

        return get(SCIM_CLIENT_ID, getClientId());
    }

    public String getScimClientSecret() {

        return get(SCIM_CLIENT_SECRET, getClientSecret());
    }

    public String getScimCustomSchemaUrn() {

        return get(SCIM_CUSTOM_SCHEMA_URN, "urn:scim:wso2:schema");
    }

    public String getAdminRoleName() {

        return get(ADMIN_ROLE_NAME, "PortalAdmin");
    }

    public String getImpersonationScope() {

        return get(IMPERSONATION_SCOPE, "internal_user_impersonate");
    }

    public String getImpersonationRedirectUri() {

        String value = get(IMPERSONATION_REDIRECT_URI);
        return value == null ? "" : value.trim();
    }

    /**
     * Issuer every token this portal accepts must carry.
     *
     * <p>Pinning it stops a token minted by some other issuer from being
     * accepted on the strength of a signature alone, and costs nothing: the
     * Identity Server names itself in {@code iss} on every token it issues.
     */
    public String getExpectedIssuer() {

        return get(EXPECTED_ISSUER, getIdentityServerBaseUrl() + "/oauth2/token");
    }

    /**
     * Expected audience of a mask token. Falls back to the portal's own OAuth
     * client, since the mask token is issued by the same Identity Server to the
     * same client as the portal's login tokens.
     */
    public String getMaskAudience() {

        return get(MASK_AUDIENCE, getClientId());
    }

    /**
     * Namespace shared by all portal-owned scopes. Set to an empty string when
     * the identity provider uses unprefixed scopes.
     */
    public String getScopePrefix() {

        return get(SCOPE_PREFIX, "portal:");
    }

    /**
     * Base URL of the Consent Server that owns consent records.
     *
     * <p>The acting routes read and write consents through this service rather
     * than through the Identity Server's own consent APIs, so that a nominee
     * acting for an owner reaches exactly the same records, through exactly the
     * same API, as the Go BFF does.
     */
    public String getConsentServerUrl() {

        String value = get(CONSENT_SERVER_URL);
        return value == null ? "" : trimTrailingSlash(value.trim());
    }

    /**
     * Client id sent upstream as {@code TPP-client-id} when a consent carries
     * none of its own.
     */
    public String getConsentServerPlaceholderClientId() {

        return get(CONSENT_SERVER_PLACEHOLDER_CLIENT_ID, "");
    }

    /** True when the nominee delegation feature has the configuration it needs. */
    public boolean isNomineeFeatureConfigured() {

        return !getNomineeServiceUrl().isEmpty() && !getNomineeGateApiKey().isEmpty()
                && !getConsentServerUrl().isEmpty();
    }

    private static String trimTrailingSlash(String value) {

        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
