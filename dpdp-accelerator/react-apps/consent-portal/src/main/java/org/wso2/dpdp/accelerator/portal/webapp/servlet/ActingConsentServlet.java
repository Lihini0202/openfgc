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
import org.wso2.dpdp.accelerator.portal.webapp.client.ConsentServerClient;
import org.wso2.dpdp.accelerator.portal.webapp.client.NomineeServiceClient;
import org.wso2.dpdp.accelerator.portal.webapp.model.MaskToken;
import org.wso2.dpdp.accelerator.portal.webapp.service.ConsentApprovalBuilder;
import org.wso2.dpdp.accelerator.portal.webapp.service.MaskTokenVerifier;
import org.wso2.dpdp.accelerator.portal.webapp.util.CookieUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConfig;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalScopes;
import org.wso2.dpdp.accelerator.portal.webapp.util.TextUtil;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The mask-token consent routes: a nominee reading and acting on the consents of
 * the owner who nominated them.
 *
 * <p>Mapped on a longer prefix than {@link ActingSessionServlet}, so the
 * container routes {@code /acting/consents...} here and the session lifecycle
 * paths there.
 */
@WebServlet(urlPatterns = "/acting-api/consents/*")
public class ActingConsentServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(ActingConsentServlet.class);

    /**
     * Binds one acting operation to the two independent things that must both
     * hold before it proceeds.
     *
     * <p><b>scope</b> is what the Identity Server minted into the token, narrowed
     * at mint time to what the owner granted — a <em>ceiling</em> fixed at session
     * start. <b>permission</b> is what Nominee Service says the owner grants right
     * now, re-read on every request — the <em>live</em> value.
     *
     * <p>Both are required. The scope alone would go stale the moment an owner
     * edits a grant or an administrator deactivates; the live check alone would
     * leave an over-privileged token in circulation.
     */
    private static final class Policy {

        private final String scope;
        private final String permission;

        Policy(String scope, String permission) {

            this.scope = scope;
            this.permission = permission;
        }
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String pathInfo = request.getPathInfo() == null ? "/" : request.getPathInfo();
        String method = request.getMethod();
        String[] segments = pathInfo.split("/");
        // segments[0] is always empty because pathInfo starts with '/'.
        String consentId = segments.length > 1 ? segments[1].trim() : "";
        String action = segments.length > 2 ? segments[2].trim() : "";

        PortalScopes scopes = scopes();

        if (consentId.isEmpty() && "GET".equals(method)) {
            listConsents(request, response, new Policy(scopes.consentsReadSelf(),
                    PortalConstants.PERMISSION_CONSENT_VIEW));
            return;
        }
        if (!consentId.isEmpty() && action.isEmpty() && "GET".equals(method)) {
            getConsent(request, response, consentId, new Policy(scopes.consentsReadSelf(),
                    PortalConstants.PERMISSION_CONSENT_VIEW));
            return;
        }
        if (!consentId.isEmpty() && "revoke".equals(action) && "POST".equals(method)) {
            revokeConsent(request, response, consentId, new Policy(scopes.consentsWriteSelf(),
                    PortalConstants.PERMISSION_CONSENT_REVOKE));
            return;
        }
        if (!consentId.isEmpty() && "approve".equals(action) && "POST".equals(method)) {
            approveConsent(request, response, consentId, new Policy(scopes.consentsApproveSelf(),
                    PortalConstants.PERMISSION_CONSENT_APPROVE));
            return;
        }
        HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                PortalConstants.ERROR_NOT_FOUND, "No such acting consent route.");
    }

    /**
     * The single authorization decision for every acting route.
     *
     * <p>Order matters: the token is verified cryptographically first, so nothing
     * downstream ever reads an unauthenticated claim; then the token's scope
     * ceiling; then the live gate. Every failure path denies — there is no branch
     * that falls through to allow.
     *
     * <p>Returns null when the request was refused, having already written the
     * response.
     */
    private MaskToken enforce(HttpServletRequest request, HttpServletResponse response,
                              Policy policy, String resourceId) throws IOException {

        PortalConfig config = config();
        String raw = maskTokenFrom(request);
        if (raw.isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    PortalConstants.ERROR_INVALID_TOKEN, "Missing impersonation token.");
            return null;
        }

        MaskToken mask;
        try {
            mask = MaskTokenVerifier.getInstance(config).verify(raw);
        } catch (MaskTokenVerifier.VerifierUnavailableException e) {
            // The token may well be valid; we simply cannot check it right now.
            // Never read as permission to proceed.
            LOG.error("Cannot verify mask token", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_VERIFIER_UNAVAILABLE,
                    "Token verification is temporarily unavailable.");
            return null;
        } catch (MaskTokenVerifier.MaskUnverifiedException e) {
            // Deliberately generic: the specific validation failure is logged,
            // not returned, so a caller cannot probe for which check failed.
            LOG.warn("Mask token rejected", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    PortalConstants.ERROR_INVALID_TOKEN, "Invalid impersonation token.");
            return null;
        }

        // The caller may state which owner it believes this session is for. The
        // acting cookie is one name at one path, so a browser holds exactly one
        // acting session across all its tabs; starting a second one for a
        // different owner replaces the first. Without this check the older tab
        // keeps its own heading and quietly renders the newer owner's records —
        // every server-side check passes, because the token really is valid for
        // that owner. Only the tab is wrong, and only the tab can say so.
        //
        // An absent header asserts nothing and is allowed: direct API callers
        // hold no tab state. This resolves a disagreement about which session is
        // in play; it is not an authorization boundary, and the checks that are
        // one all run below regardless.
        String claimedOwner = request.getHeader(PortalConstants.ACTING_OWNER_HEADER);
        if (claimedOwner != null && !claimedOwner.trim().isEmpty()
                && !claimedOwner.trim().equals(mask.getOwner())) {
            LOG.warn("Caller expected a different owner than the token carries: claimed "
                    + LogUtil.sanitize(claimedOwner) + " token " + LogUtil.sanitize(mask.getOwner()));
            HttpUtil.sendError(response, HttpServletResponse.SC_CONFLICT,
                    PortalConstants.ERROR_ACTING_OWNER_MISMATCH,
                    "This acting session is for a different owner.");
            return null;
        }

        NomineeServiceClient nominee = new NomineeServiceClient(config);

        // The scope ceiling fixed at mint time. A nominee granted view-only holds
        // a token that never carried the write scope, so this denies before the
        // gate is even consulted.
        if (!mask.hasScope(policy.scope)) {
            LOG.warn("Mask token lacks required scope " + LogUtil.sanitize(policy.scope));
            nominee.recordAction(mask.getOwner(), mask.getNominee(), policy.permission, resourceId,
                    false, "token does not carry " + policy.scope);
            HttpUtil.sendError(response, HttpServletResponse.SC_FORBIDDEN,
                    PortalConstants.ERROR_INSUFFICIENT_SCOPE,
                    "Impersonation token does not carry " + policy.scope + ".");
            return null;
        }

        // The live decision. This is what makes deactivation take effect on the
        // next request rather than at token expiry.
        NomineeServiceClient.Decision decision;
        try {
            decision = nominee.permissions(mask.getOwner(), mask.getNominee());
        } catch (NomineeServiceClient.GateUnavailableException e) {
            LOG.error("Nomination gate call failed", e);
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                    PortalConstants.ERROR_GATE_UNAVAILABLE, "Permission check failed.");
            return null;
        }
        if (!decision.isActive()) {
            nominee.recordAction(mask.getOwner(), mask.getNominee(), policy.permission, resourceId,
                    false, "no active nomination");
            HttpUtil.sendError(response, HttpServletResponse.SC_FORBIDDEN,
                    PortalConstants.ERROR_NOT_ACTIVE_NOMINEE, "No active nomination for this owner.");
            return null;
        }
        if (!decision.grants(policy.permission)) {
            nominee.recordAction(mask.getOwner(), mask.getNominee(), policy.permission, resourceId,
                    false, "permission not granted");
            HttpUtil.sendError(response, HttpServletResponse.SC_FORBIDDEN,
                    PortalConstants.ERROR_PERMISSION_DENIED,
                    "Owner did not grant " + policy.permission + " to this nominee.");
            return null;
        }

        nominee.recordAction(mask.getOwner(), mask.getNominee(), policy.permission, resourceId, true, "");
        return mask;
    }

    /**
     * Extracts the raw mask token from a request.
     *
     * <p>The HttpOnly cookie set by the exchange is preferred: it keeps the token
     * out of JavaScript entirely. The Authorization header remains accepted so
     * service-to-service callers and tests can present a token directly.
     */
    private static String maskTokenFrom(HttpServletRequest request) {

        String cookie = CookieUtil.getCookieValue(request, PortalConstants.ACTING_TOKEN_COOKIE);
        if (cookie != null && !cookie.trim().isEmpty()) {
            return cookie.trim();
        }
        String header = request.getHeader("Authorization");
        if (header == null || header.length() < 7
                || !TextUtil.equalsFolded(header.substring(0, 7), "bearer ")) {
            return "";
        }
        return header.substring(7).trim();
    }

    /** {@code GET /acting-api/consents} — the owner's consents, and only the owner's. */
    private void listConsents(HttpServletRequest request, HttpServletResponse response, Policy policy)
            throws IOException {

        MaskToken mask = enforce(request, response, policy, "");
        if (mask == null) {
            return;
        }
        // The owner is fixed from the verified token; the caller's own filters
        // are forwarded on top, so a nominee's listing filters and pages exactly
        // as the owner's own does.
        StringBuilder query = new StringBuilder(ConsentServerClient.CONSENTS_API)
                .append("?userIds=").append(URLEncoder.encode(mask.getOwner(), StandardCharsets.UTF_8))
                .append("&details=true");
        MeConsentsServlet.appendListParams(request, query);
        try {
            relay(consentServer(mask).get(query.toString()), response);
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /**
     * {@code GET /acting-api/consents/{id}} — one consent, after confirming it is the
     * owner's.
     *
     * <p>The upstream lookup is by id alone and will happily return any consent in
     * the organisation, so without this check a nominee holding a valid mask token
     * could read a consent belonging to somebody who never nominated them, simply
     * by knowing its id. A consent owned by anyone else is reported as absent
     * rather than forbidden, which keeps the response from confirming the id
     * exists.
     */
    private void getConsent(HttpServletRequest request, HttpServletResponse response,
                            String consentId, Policy policy) throws IOException {

        MaskToken mask = enforce(request, response, policy, consentId);
        if (mask == null) {
            return;
        }
        try {
            ConsentServerClient.Result result = consentServer(mask)
                    .get(ConsentServerClient.CONSENTS_API + "/" + URLEncoder.encode(consentId,
                            StandardCharsets.UTF_8));
            if (result.getStatus() == HttpServletResponse.SC_OK
                    && !consentBelongsTo(result.getBody(), mask.getOwner())) {
                LOG.warn("Consent " + LogUtil.sanitize(consentId) + " does not belong to the owner");
                HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                        "CONSENT_NOT_FOUND", "Consent not found.");
                return;
            }
            relay(result, response);
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /**
     * {@code POST /acting-api/consents/{id}/revoke}.
     *
     * <p>{@code actionBy} is the nominee, never the owner: the audit trail must
     * name the real human who acted.
     */
    private void revokeConsent(HttpServletRequest request, HttpServletResponse response,
                               String consentId, Policy policy) throws IOException {

        MaskToken mask = enforce(request, response, policy, consentId);
        if (mask == null) {
            return;
        }
        ConsentServerClient client = consentServer(mask);
        String path = ConsentServerClient.CONSENTS_API + "/"
                + URLEncoder.encode(consentId, StandardCharsets.UTF_8);
        try {
            // Fetched first for the same reason as the detail route: the
            // upstream lookup is by id alone, so without this a nominee could
            // revoke a consent belonging to somebody who never nominated them.
            // It also yields the group the write is authorised against.
            ConsentServerClient.Result current = client.get(path);
            if (current.getStatus() != HttpServletResponse.SC_OK) {
                relay(current, response);
                return;
            }
            String groupId = MeConsentsServlet.ownedGroupId(current.getBody(), mask.getOwner());
            if (groupId == null) {
                LOG.warn("Consent " + LogUtil.sanitize(consentId) + " does not belong to the owner");
                HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                        "CONSENT_NOT_FOUND", "Consent not found.");
                return;
            }
            ObjectNode payload = HttpUtil.mapper().createObjectNode();
            payload.put("actionBy", mask.getNominee());
            relay(client.post(path + "/revoke", payload.toString(), groupId), response);
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /**
     * {@code POST /acting-api/consents/{id}/approve}.
     *
     * <p>Approving is separated from revoking throughout — a distinct permission
     * and a distinct scope — because the two are opposite acts. Revoking withdraws
     * processing the owner already chose; approving authorises new processing on
     * their behalf. Granting one must never confer the other.
     *
     * <p>The approval is recorded against the <em>owner</em>, whose consent it is.
     * Who performed it is carried by the audit trail, which names the nominee.
     */
    private void approveConsent(HttpServletRequest request, HttpServletResponse response,
                                String consentId, Policy policy) throws IOException {

        MaskToken mask = enforce(request, response, policy, consentId);
        if (mask == null) {
            return;
        }

        String body = readBody(request);
        if (body.length() > PortalConstants.MAX_REQUEST_BYTES) {
            HttpUtil.sendError(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "REQUEST_TOO_LARGE", "Request entity too large.");
            return;
        }

        ConsentServerClient client = consentServer(mask);
        try {
            ConsentServerClient.Result current = client.get(ConsentServerClient.CONSENTS_API + "/"
                    + URLEncoder.encode(consentId, StandardCharsets.UTF_8));
            if (current.getStatus() != HttpServletResponse.SC_OK) {
                relay(current, response);
                return;
            }
            if (!consentBelongsTo(current.getBody(), mask.getOwner())) {
                LOG.warn("Consent " + LogUtil.sanitize(consentId) + " does not belong to the owner");
                HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                        "CONSENT_NOT_FOUND", "Consent not found.");
                return;
            }

            ConsentApprovalBuilder.Payload approval = new ConsentApprovalBuilder(client)
                    .build(current.getBody(), body, mask.getOwner());
            ConsentServerClient.Result result = client.put(ConsentServerClient.CONSENTS_API + "/"
                    + URLEncoder.encode(consentId, StandardCharsets.UTF_8),
                    approval.getBody(), approval.getGroupId());
            relay(result, response);
        } catch (ConsentApprovalBuilder.InvalidSelectionException e) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "Invalid request payload.");
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /**
     * Reports whether the owner holds an authorization on the consent described
     * by {@code body}. A body that cannot be parsed yields false, so a response
     * this code does not understand is never treated as the owner's.
     */
    static boolean consentBelongsTo(String body, String ownerId) {

        try {
            JsonNode consent = HttpUtil.mapper().readTree(body);
            for (JsonNode authorization : consent.path("authorizations")) {
                if (ownerId.equals(authorization.path("userId").asText(null))) {
                    return true;
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    private ConsentServerClient consentServer(MaskToken mask) {

        return new ConsentServerClient(config(), mask.getOrganizationId());
    }

    /** Relays an upstream result to the SPA verbatim. */
    private static void relay(ConsentServerClient.Result result, HttpServletResponse response)
            throws IOException {

        response.setStatus(result.getStatus());
        if (result.getBody() != null && !result.getBody().isEmpty()) {
            response.setContentType(PortalConstants.CONTENT_TYPE_JSON);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(result.getBody());
        }
    }

    private static void sendUpstreamUnavailable(HttpServletResponse response, Exception cause)
            throws IOException {

        LOG.error("Consent server unavailable", cause);
        HttpUtil.sendError(response, HttpServletResponse.SC_BAD_GATEWAY,
                PortalConstants.ERROR_UPSTREAM, "The consent service is unavailable.");
    }
}
