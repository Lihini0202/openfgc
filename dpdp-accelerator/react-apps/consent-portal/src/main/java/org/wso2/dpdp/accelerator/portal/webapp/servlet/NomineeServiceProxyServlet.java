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
import org.wso2.dpdp.accelerator.portal.webapp.service.OAuthService;
import org.wso2.dpdp.accelerator.portal.webapp.util.CookieUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Same-origin passthrough to Nominee Service, which owns the nomination records.
 *
 * <p>The SPA cannot call Nominee Service directly from this deployment. The
 * portal is served over https from the Identity Server while Nominee Service
 * listens on plain http, which browsers block as active mixed content, and its
 * CORS allowlist names the standalone portal's origins rather than this one.
 * Routing through the webapp removes both problems at once: the request is
 * same-origin, so there is no mixed content and no preflight.
 *
 * <p>The caller's credentials are forwarded untouched rather than re-minted.
 * Nominee Service performs its own split-token reassembly - part one from the
 * Authorization header, part two from the HttpOnly cookie - and validates the
 * result itself, so it must receive exactly what the browser sent. This servlet
 * decides nothing about authorization.
 */
@WebServlet(urlPatterns = "/nominee-service/*")
public class NomineeServiceProxyServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(NomineeServiceProxyServlet.class);

    /** Methods the nomination screens use. Anything else is refused outright. */
    private static final Set<String> ALLOWED_METHODS = Set.of("GET", "POST", "PATCH", "DELETE");

    /**
     * Path segments this proxy will relay. Constrained so a caller cannot steer
     * the upstream request outside Nominee Service's own API surface.
     */
    private static final Pattern SAFE_PATH = Pattern.compile("[A-Za-z0-9._~/-]*");

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String method = request.getMethod();
        if (!ALLOWED_METHODS.contains(method)) {
            HttpUtil.sendError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    "METHOD_NOT_ALLOWED", method + " is not supported by this endpoint.");
            return;
        }

        PortalConfig config = config();
        String baseUrl = config.getNomineeServiceUrl();
        if (baseUrl.isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "NOMINEE_SERVICE_NOT_CONFIGURED", "Nominee Service is not configured.");
            return;
        }

        String path = request.getPathInfo() == null ? "/" : request.getPathInfo();
        if (!SAFE_PATH.matcher(path).matches() || path.contains("..")) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_BAD_REQUEST, "Unsupported path.");
            return;
        }
        String query = request.getQueryString();
        String target = baseUrl + path + (query == null || query.isEmpty() ? "" : "?" + query);

        // Both halves of the caller's token, exactly as the browser presented
        // them. Nominee Service rejoins and validates them itself.
        String authorization = request.getHeader("Authorization");
        String part2 = CookieUtil.getCookieValue(request, PortalConstants.ACCESS_TOKEN_PART2_COOKIE);
        if (authorization == null || part2 == null) {
            HttpUtil.sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    PortalConstants.ERROR_UNAUTHORIZED, "Authentication is required.");
            return;
        }

        String body = readBody(request);
        if (body.length() > PortalConstants.MAX_REQUEST_BYTES) {
            HttpUtil.sendError(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "REQUEST_TOO_LARGE", "Request entity too large.");
            return;
        }

        HttpRequest.BodyPublisher publisher = body.isEmpty()
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(target))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", authorization)
                .header("Cookie", PortalConstants.ACCESS_TOKEN_PART2_COOKIE + "=" + part2)
                .header("Accept", PortalConstants.CONTENT_TYPE_JSON)
                .method(method, publisher);
        if (!body.isEmpty()) {
            builder.header("Content-Type", PortalConstants.CONTENT_TYPE_JSON);
        }

        try {
            HttpResponse<String> upstream = OAuthService.getInstance().httpClient()
                    .send(builder.build(), HttpResponse.BodyHandlers.ofString());
            response.setStatus(upstream.statusCode());
            String payload = upstream.body();
            if (payload != null && !payload.isEmpty()) {
                response.setContentType(PortalConstants.CONTENT_TYPE_JSON);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.getWriter().write(payload);
            }
        } catch (IOException e) {
            LOG.error("Nominee Service request failed: " + LogUtil.sanitize(method + " " + path), e);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_UPSTREAM, "The nomination service is unavailable.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_UPSTREAM, "The nomination service is unavailable.");
        }
    }
}
