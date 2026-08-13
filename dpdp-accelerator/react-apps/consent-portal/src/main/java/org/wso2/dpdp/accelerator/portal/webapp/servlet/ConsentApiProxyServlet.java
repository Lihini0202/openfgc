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
import org.wso2.dpdp.accelerator.portal.webapp.client.ConsentServerClient;
import org.wso2.dpdp.accelerator.portal.webapp.model.AuthenticatedUser;
import org.wso2.dpdp.accelerator.portal.webapp.service.ConsentApiRoutes;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The administrative and catalog passthrough to the Consent Server.
 *
 * <p>Operations are allowlisted rather than forwarded wholesale: the upstream
 * exposes more than the portal has any business calling, and a new upstream
 * route must be a deliberate decision here before a browser can reach it. Each
 * entry names the scope it requires, so authority is declared next to the
 * operation it guards rather than inferred from the path at request time.
 */
@WebServlet(urlPatterns = "/api/*")
public class ConsentApiProxyServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(ConsentApiProxyServlet.class);

    /** Path segments the portal accepts; anything else is refused before use. */
    private static final Pattern SAFE_PATH = Pattern.compile("[A-Za-z0-9._~/-]*");

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String pathInfo = request.getPathInfo() == null ? "" : request.getPathInfo();
        if (!SAFE_PATH.matcher(pathInfo).matches() || pathInfo.contains("..")) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_BAD_REQUEST, "Unsupported path.");
            return;
        }
        ConsentApiRoutes.Match match = ConsentApiRoutes.match(request.getMethod(), pathInfo);
        if (match.getDecision() == ConsentApiRoutes.Decision.METHOD_NOT_ALLOWED) {
            HttpUtil.sendError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    "METHOD_NOT_ALLOWED", request.getMethod() + " is not supported by this endpoint.");
            return;
        }
        if (match.getDecision() != ConsentApiRoutes.Decision.ALLOWED) {
            LOG.warn("Refused a non-allowlisted upstream operation: "
                    + LogUtil.sanitize(request.getMethod() + " " + pathInfo));
            HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                    PortalConstants.ERROR_NOT_FOUND, "No such API route.");
            return;
        }

        AuthenticatedUser user = requireScope(request, response, scopeFor(match.getScope()));
        if (user == null) {
            return;
        }

        String body = readBody(request);
        if (body.length() > PortalConstants.MAX_REQUEST_BYTES) {
            HttpUtil.sendError(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "REQUEST_TOO_LARGE", "Request entity too large.");
            return;
        }
        String query = request.getQueryString();
        String relativePath = pathInfo.startsWith("/") ? pathInfo.substring(1) : pathInfo;
        String target = "/api/v1/" + relativePath + (query == null || query.isEmpty() ? "" : "?" + query);

        try {
            ConsentServerClient client = new ConsentServerClient(config(), user.getOrganizationId());
            ConsentServerClient.Result result = client.relay(request.getMethod(), target, body);
            response.setStatus(result.getStatus());
            if (result.getBody() != null && !result.getBody().isEmpty()) {
                response.setContentType(PortalConstants.CONTENT_TYPE_JSON);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.getWriter().write(result.getBody());
            }
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            LOG.error("Consent server unavailable", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_UPSTREAM, "The consent service is unavailable.");
        }
    }

    private String scopeFor(ConsentApiRoutes.Scope scope) {

        switch (scope) {
            case CONSENTS_READ_ANY:
                return scopes().consentsReadAny();
            case CONSENTS_WRITE_ANY:
                return scopes().consentsWriteAny();
            case ELEMENTS_READ:
                return scopes().elementsRead();
            case ELEMENTS_WRITE:
                return scopes().elementsWrite();
            case PURPOSES_READ:
                return scopes().purposesRead();
            default:
                return scopes().purposesWrite();
        }
    }
}
