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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dpdp.accelerator.portal.webapp.client.ImpersonationClient;
import org.wso2.dpdp.accelerator.portal.webapp.client.NomineeServiceClient;
import org.wso2.dpdp.accelerator.portal.webapp.model.MaskToken;
import org.wso2.dpdp.accelerator.portal.webapp.service.MaskTokenVerifier;
import org.wso2.dpdp.accelerator.portal.webapp.util.AuthUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.CookieUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalScopes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The acting-session lifecycle: {@code GET /acting-api/start},
 * {@code POST /acting-api/exchange} and {@code POST /acting-api/stop}.
 *
 * <p>All three share one servlet because the container dispatches on a path
 * prefix rather than on route patterns.
 *
 * <p>Mapped under {@code /acting-api} rather than {@code /acting}: the SPA owns
 * {@code /acting/:ownerId} and {@code /acting/callback} as client-side routes,
 * and it is served from this same origin. A servlet on {@code /acting/*} would
 * claim those paths before the SPA could render them - including the callback
 * the Identity Server redirects to, which would end the impersonation flow with
 * a JSON 404 instead of a page.
 */
@WebServlet(urlPatterns = "/acting-api/*")
public class ActingSessionServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(ActingSessionServlet.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String action = pathSegment(request);
        String method = request.getMethod();

        if ("start".equals(action) && "GET".equals(method)) {
            start(request, response);
            return;
        }
        if ("exchange".equals(action) && "POST".equals(method)) {
            exchange(request, response);
            return;
        }
        if ("stop".equals(action) && "POST".equals(method)) {
            stop(request, response);
            return;
        }
        // Consent routes under /acting-api/ are served by ActingConsentServlet; a
        // path this servlet does not own is reported as absent, in the JSON
        // envelope the SPA expects rather than as an HTML error page.
        HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                PortalConstants.ERROR_NOT_FOUND, "No such acting route: " + action);
    }

    /**
     * {@code GET /acting-api/start?ownerId=} — redirects to the Identity Server's
     * authorization endpoint.
     *
     * <p>This must be a real top-level navigation, not a fetch: the request has
     * to carry the Identity Server's session cookie, and the response is a
     * cross-origin redirect whose fragment only the browser can read.
     */
    private void start(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String ownerId = request.getParameter("ownerId");
        ownerId = ownerId == null ? "" : ownerId.trim();
        if (ownerId.isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "ownerId is required");
            return;
        }

        PortalConfig config = config();
        String state = randomToken();
        String nonce = randomToken();

        try {
            String authorizeUrl = new ImpersonationClient(config)
                    .authorizeUrl(ownerId, state, nonce, new PortalScopes(config).delegatable());
            // The state cookie binds the callback to this browser. It carries the
            // owner so the exchange can report which acting session was
            // established without trusting anything the callback supplies.
            CookieUtil.addCookie(response, PortalConstants.ACTING_STATE_COOKIE, state + "|" + ownerId,
                    config.getPortalBasePath(), PortalConstants.ACTING_STATE_MAX_AGE_SECONDS,
                    true, config.isCookieSecure(), "Strict");
            response.sendRedirect(authorizeUrl);
        } catch (ImpersonationClient.NotConfiguredException e) {
            LOG.error("Acting start refused: impersonation is not configured", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "IDENTITY_SERVER_NOT_CONFIGURED", "Identity server impersonation is not configured.");
        }
    }

    /**
     * {@code POST /acting-api/exchange} — turns the subject token the browser read
     * out of the URL fragment into a usable impersonation token.
     *
     * <p>The exchange needs the client secret, which is why it runs server-side:
     * a subject token leaked from the fragment is not usable on its own.
     */
    private void exchange(HttpServletRequest request, HttpServletResponse response) throws IOException {

        PortalConfig config = config();
        NomineeServiceClient nominee = new NomineeServiceClient(config);

        JsonNode body;
        try {
            body = HttpUtil.mapper().readTree(readBody(request));
        } catch (IOException e) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "subjectToken and state are required");
            return;
        }
        String subjectToken = body.path("subjectToken").asText("").trim();
        String suppliedState = body.path("state").asText("").trim();
        if (subjectToken.isEmpty() || suppliedState.isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "subjectToken and state are required");
            return;
        }

        String stateCookie = CookieUtil.getCookieValue(request, PortalConstants.ACTING_STATE_COOKIE);
        if (stateCookie == null || stateCookie.trim().isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_STATE, "no acting flow in progress");
            return;
        }
        int separator = stateCookie.indexOf('|');
        if (separator <= 0) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_STATE, "no acting flow in progress");
            return;
        }
        String expectedState = stateCookie.substring(0, separator);
        String ownerId = stateCookie.substring(separator + 1);

        // Constant-time: state is a secret bound to this browser, so comparing it
        // must not leak position information through timing.
        if (!MessageDigest.isEqual(expectedState.getBytes(StandardCharsets.UTF_8),
                suppliedState.getBytes(StandardCharsets.UTF_8))) {
            clearActingCookie(response, PortalConstants.ACTING_STATE_COOKIE);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_STATE, "acting state mismatch");
            return;
        }
        clearActingCookie(response, PortalConstants.ACTING_STATE_COOKIE);

        // The nominee's own access token, sent to the Identity Server as the
        // RFC 8693 actor_token. It compares that token's subject against the
        // subject token's may_act claim, so the exchange only succeeds for the
        // nominee actually named in it.
        String actorToken = AuthUtil.resolveAccessToken(request);
        if (actorToken == null) {
            HttpUtil.sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "NOT_AUTHENTICATED", "You must be signed in to start an acting session.");
            return;
        }

        ImpersonationClient.Token token;
        try {
            token = new ImpersonationClient(config).exchangeSubjectToken(subjectToken, actorToken);
        } catch (ImpersonationClient.NotConfiguredException e) {
            LOG.error("Acting exchange refused: impersonation is not configured", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "IDENTITY_SERVER_NOT_CONFIGURED", "Identity server impersonation is not configured.");
            return;
        } catch (ImpersonationClient.IdentityServerUnavailableException e) {
            // The client gets a generic error, but the operator needs the reason:
            // a failed exchange is almost always an Identity Server configuration
            // problem and is otherwise invisible from this side.
            LOG.error("Subject token exchange failed for owner " + LogUtil.sanitize(ownerId), e);
            nominee.record(ownerId, "", PortalConstants.EVENT_SESSION_DENIED, "exchange failed");
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    "IDENTITY_SERVER_UNAVAILABLE", "Identity server unavailable.");
            return;
        }

        // Verify what was just received rather than trusting the exchange. This
        // also resolves the real owner/nominee pair, which is what the response
        // reports.
        MaskToken mask;
        try {
            mask = MaskTokenVerifier.getInstance(config).verify(token.getAccessToken());
        } catch (MaskTokenVerifier.MaskUnverifiedException e) {
            LOG.error("Exchange returned a token that failed verification", e);
            nominee.record(ownerId, "", PortalConstants.EVENT_SESSION_DENIED,
                    "exchanged token failed verification");
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_INVALID_TOKEN,
                    "Identity server returned an unusable impersonation token.");
            return;
        } catch (MaskTokenVerifier.VerifierUnavailableException e) {
            LOG.error("Cannot verify the exchanged token", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_VERIFIER_UNAVAILABLE,
                    "Token verification is temporarily unavailable.");
            return;
        }

        // The token must describe the session the browser actually started. A
        // mismatch means the callback was crossed with another flow.
        if (!ownerId.isEmpty() && !ownerId.equals(mask.getOwner())) {
            LOG.warn("Exchanged token subject does not match the started session: expected "
                    + LogUtil.sanitize(ownerId) + " but the token names " + LogUtil.sanitize(mask.getOwner()));
            nominee.record(ownerId, mask.getNominee(), PortalConstants.EVENT_SESSION_DENIED,
                    "session mismatch");
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_STATE, "acting session mismatch");
            return;
        }

        // In subject-token mode the expiry comes from the verified token itself,
        // since the exchange response carried none.
        Instant expiresAt = token.getExpiresAt() != null ? token.getExpiresAt() : mask.getExpiry();
        long ttlSeconds = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        if (ttlSeconds <= 0) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_INVALID_TOKEN, "Identity server returned an expired token.");
            return;
        }

        CookieUtil.addCookie(response, PortalConstants.ACTING_TOKEN_COOKIE, token.getAccessToken(),
                config.getPortalBasePath(), (int) ttlSeconds, true, config.isCookieSecure(), "Strict");

        String scopeList = String.join(",", mask.getScopes());
        nominee.record(mask.getOwner(), mask.getNominee(), PortalConstants.EVENT_SESSION_STARTED,
                "scopes=" + scopeList);

        ObjectNode payload = HttpUtil.mapper().createObjectNode();
        payload.put("ownerId", mask.getOwner());
        payload.put("nomineeId", mask.getNominee());
        payload.set("scopes", HttpUtil.mapper().valueToTree(mask.getScopes()));
        payload.put("expiresAt", DateTimeFormatter.ISO_INSTANT.format(expiresAt));
        HttpUtil.sendJson(response, HttpServletResponse.SC_OK, payload);
    }

    /**
     * {@code POST /acting-api/stop} — ends the acting session for this browser by
     * clearing its cookies.
     *
     * <p>The Identity Server cannot revoke an already-issued impersonation token,
     * which is why its lifetime is kept short and why every acting request
     * re-checks the nomination gate regardless.
     */
    private void stop(HttpServletRequest request, HttpServletResponse response) {

        clearActingCookie(response, PortalConstants.ACTING_TOKEN_COOKIE);
        clearActingCookie(response, PortalConstants.ACTING_STATE_COOKIE);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Expires an acting cookie, keeping HttpOnly and SameSite identical to the
     * values it was set with so the browser matches and replaces it.
     */
    private void clearActingCookie(HttpServletResponse response, String name) {

        PortalConfig config = config();
        CookieUtil.addCookie(response, name, "", config.getPortalBasePath(), 0,
                true, config.isCookieSecure(), "Strict");
    }

    private static String randomToken() {

        byte[] buffer = new byte[32];
        RANDOM.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }
}
