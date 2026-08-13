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

package org.wso2.dpdp.accelerator.portal.webapp.servlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dpdp.accelerator.portal.webapp.client.ScimDirectoryClient;
import org.wso2.dpdp.accelerator.portal.webapp.exception.TokenValidationException;
import org.wso2.dpdp.accelerator.portal.webapp.model.AuthenticatedUser;
import org.wso2.dpdp.accelerator.portal.webapp.service.TokenValidator;
import org.wso2.dpdp.accelerator.portal.webapp.util.AuthUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalScopes;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Shared authorization for the nominee route group.
 *
 * <p>The Java BFF has no middleware chain, so the scope check the Go BFF applies
 * at route registration is applied here instead, at the top of each handler. The
 * decision is the same one: a caller must present a verified token that carries
 * the scope the route requires.
 */
public abstract class AbstractNomineeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(AbstractNomineeServlet.class);

    protected PortalConfig config() {

        return PortalConfig.getInstance(getServletContext());
    }

    protected PortalScopes scopes() {

        return new PortalScopes(config());
    }

    protected ScimDirectoryClient directory() {

        return ScimDirectoryClient.getInstance(config());
    }

    /**
     * Verifies the caller's token and checks one required scope, writing the
     * refusal itself and returning null when either step fails.
     *
     * <p>The token is validated cryptographically rather than merely read: the
     * split-token pair proves only that the browser holds both halves, not that
     * the Identity Server issued them.
     */
    protected AuthenticatedUser requireScope(HttpServletRequest request, HttpServletResponse response,
                                             String requiredScope) throws IOException {

        String accessToken = AuthUtil.resolveAccessToken(request);
        if (accessToken == null) {
            HttpUtil.sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    PortalConstants.ERROR_UNAUTHORIZED, "Authentication is required.");
            return null;
        }

        AuthenticatedUser user;
        try {
            user = TokenValidator.getInstance(config()).validate(accessToken);
        } catch (TokenValidationException e) {
            // Deliberately generic to the caller: which check failed is logged,
            // never returned, so a client cannot probe validation behaviour.
            LOG.warn("Nominee route rejected an unverifiable access token", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    PortalConstants.ERROR_UNAUTHORIZED, "Access token is invalid or expired.");
            return null;
        }

        if (requiredScope != null && !user.hasScope(requiredScope)) {
            LOG.warn("Nominee route denied: token lacks " + LogUtil.sanitize(requiredScope));
            HttpUtil.sendError(response, HttpServletResponse.SC_FORBIDDEN,
                    PortalConstants.ERROR_INSUFFICIENT_SCOPE, "Access token does not carry " + requiredScope + ".");
            return null;
        }
        return user;
    }

    /**
     * Adds the administrator barrier to a caller that has already cleared
     * {@link #requireScope}.
     *
     * <p>Admin routes stand behind two independent barriers: the scope says this
     * client application may call cross-user APIs, the role says this human is a
     * verified administrator. Both are required. The scope alone would let any
     * application holding it act administratively; the role alone would ignore
     * what the client was actually authorised to do.
     */
    protected boolean requireAdmin(AuthenticatedUser user, HttpServletResponse response) throws IOException {

        try {
            if (!directory().isUserInRole(config().getAdminRoleName(), user.getUserId())) {
                HttpUtil.sendError(response, HttpServletResponse.SC_FORBIDDEN,
                        PortalConstants.ERROR_ADMIN_REQUIRED, "This action requires an administrator.");
                return false;
            }
            return true;
        } catch (ScimDirectoryClient.DirectoryUnavailableException e) {
            // A directory that cannot be reached is never read as "yes".
            LOG.error("Could not evaluate the administrator role", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_IDENTITY_UNAVAILABLE, "Identity service unavailable.");
            return false;
        }
    }

    /**
     * Returns the single path segment following the servlet's mapped prefix, or
     * an empty string when the request names none.
     */
    protected static String pathSegment(HttpServletRequest request) {

        String info = request.getPathInfo();
        if (info == null) {
            return "";
        }
        String trimmed = info.startsWith("/") ? info.substring(1) : info;
        int slash = trimmed.indexOf('/');
        return (slash < 0 ? trimmed : trimmed.substring(0, slash)).trim();
    }

    protected static String readBody(HttpServletRequest request) throws IOException {

        try (BufferedReader reader = request.getReader()) {
            return reader.lines().collect(Collectors.joining());
        }
    }

    protected void sendDirectoryUnavailable(HttpServletResponse response) throws IOException {

        HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                PortalConstants.ERROR_IDENTITY_UNAVAILABLE, "Identity service unavailable.");
    }
}
