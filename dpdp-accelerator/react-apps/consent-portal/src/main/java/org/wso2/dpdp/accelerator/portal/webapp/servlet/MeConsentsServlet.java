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
import org.wso2.dpdp.accelerator.portal.webapp.model.AuthenticatedUser;
import org.wso2.dpdp.accelerator.portal.webapp.service.ConsentApprovalBuilder;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.LogUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;
import org.wso2.dpdp.accelerator.portal.webapp.util.TextUtil;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The signed-in user's own consents, served from the Consent Server.
 *
 * <p>This is the first-party counterpart of {@link ActingConsentServlet}: the
 * same records, the same upstream, but scoped to the caller themselves rather
 * than to an owner they were nominated for. Both read the Consent Server rather
 * than the Identity Server's own consent store, because that is where these
 * records live.
 *
 * <p>Every route resolves the user from a cryptographically verified token, so
 * the identity a consent is filtered or written against is never client-supplied.
 */
@WebServlet(urlPatterns = "/me/consents/*")
public class MeConsentsServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    private static final Log LOG = LogFactory.getLog(MeConsentsServlet.class);

    /**
     * Query parameters a consent listing accepts.
     *
     * <p>Forwarded explicitly rather than by copying the caller's whole query
     * string, so a parameter the portal does not intend to expose - a different
     * user filter above all - cannot ride along to the Consent Server. Shared
     * with {@link ActingConsentServlet}: a filter the owner's own listing
     * honours must behave identically when a nominee views it.
     */
    static final String[] LIST_PARAMS = {
        "consentStatuses", "purposeName", "groupIds", "elementName", "elementVersion",
        "sort", "fromTime", "toTime", "limit", "offset",
    };

    /** Appends the listing filters the caller supplied to an upstream query. */
    static void appendListParams(HttpServletRequest request, StringBuilder query) {

        for (String name : LIST_PARAMS) {
            String value = request.getParameter(name);
            if (value != null && !value.isEmpty()) {
                query.append('&').append(name).append('=')
                        .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
            }
        }
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String pathInfo = request.getPathInfo() == null ? "/" : request.getPathInfo();
        String method = request.getMethod();
        String[] segments = pathInfo.split("/");
        String consentId = segments.length > 1 ? segments[1].trim() : "";
        String action = segments.length > 2 ? segments[2].trim() : "";

        if (consentId.isEmpty() && "GET".equals(method)) {
            list(request, response);
            return;
        }
        if (!consentId.isEmpty() && action.isEmpty() && "GET".equals(method)) {
            byId(request, response, consentId);
            return;
        }
        if (!consentId.isEmpty() && "POST".equals(method)) {
            switch (action) {
                case "approve":
                    approve(request, response, consentId);
                    return;
                case "reject":
                    reject(request, response, consentId);
                    return;
                case "revoke":
                    revoke(request, response, consentId);
                    return;
                default:
                    break;
            }
        }
        HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                PortalConstants.ERROR_NOT_FOUND, "No such consent route.");
    }

    /** {@code GET /me/consents} — the caller's own consents, and only those. */
    private void list(HttpServletRequest request, HttpServletResponse response) throws IOException {

        AuthenticatedUser user = requireScope(request, response, scopes().consentsReadSelf());
        if (user == null) {
            return;
        }
        StringBuilder query = new StringBuilder(ConsentServerClient.CONSENTS_API)
                .append("?userIds=").append(encode(user.getUserId()))
                .append("&details=true");
        appendListParams(request, query);
        try {
            relay(client(user).get(query.toString()), response);
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /**
     * {@code GET /me/consents/{id}} — one consent, after confirming it is the
     * caller's.
     *
     * <p>The upstream lookup is by id alone and would return any consent in the
     * organisation. A consent belonging to somebody else is reported as absent
     * rather than forbidden, so the response cannot be used to confirm that an
     * id exists.
     */
    private void byId(HttpServletRequest request, HttpServletResponse response, String consentId)
            throws IOException {

        AuthenticatedUser user = requireScope(request, response, scopes().consentsReadSelf());
        if (user == null) {
            return;
        }
        try {
            ConsentServerClient.Result result = client(user).get(consentPath(consentId));
            if (result.getStatus() == HttpServletResponse.SC_OK
                    && ownedGroupId(result.getBody(), user.getUserId()) == null) {
                notFound(response, consentId, user);
                return;
            }
            relay(result, response);
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /** {@code POST /me/consents/{id}/approve}. */
    private void approve(HttpServletRequest request, HttpServletResponse response, String consentId)
            throws IOException {

        AuthenticatedUser user = requireScope(request, response, scopes().consentsApproveSelf());
        if (user == null) {
            return;
        }
        String body = readBody(request);
        if (body.length() > PortalConstants.MAX_REQUEST_BYTES) {
            HttpUtil.sendError(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "REQUEST_TOO_LARGE", "Request entity too large.");
            return;
        }
        ConsentServerClient client = client(user);
        try {
            ConsentServerClient.Result current = client.get(consentPath(consentId));
            if (current.getStatus() != HttpServletResponse.SC_OK) {
                relay(current, response);
                return;
            }
            if (ownedGroupId(current.getBody(), user.getUserId()) == null) {
                notFound(response, consentId, user);
                return;
            }
            ConsentApprovalBuilder.Payload approval =
                    new ConsentApprovalBuilder(client).build(current.getBody(), body, user.getUserId());
            relay(client.put(consentPath(consentId), approval.getBody(), approval.getGroupId()), response);
        } catch (ConsentApprovalBuilder.InvalidSelectionException e) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "Invalid request payload.");
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /** {@code POST /me/consents/{id}/reject} — decline a consent still pending. */
    private void reject(HttpServletRequest request, HttpServletResponse response, String consentId)
            throws IOException {

        AuthenticatedUser user = requireScope(request, response, scopes().consentsWriteSelf());
        if (user == null) {
            return;
        }
        ConsentServerClient client = client(user);
        try {
            ConsentServerClient.Result current = client.get(consentPath(consentId));
            if (current.getStatus() != HttpServletResponse.SC_OK) {
                relay(current, response);
                return;
            }
            if (ownedGroupId(current.getBody(), user.getUserId()) == null) {
                notFound(response, consentId, user);
                return;
            }
            ConsentApprovalBuilder.Payload rejection =
                    new ConsentApprovalBuilder(client).buildRejection(current.getBody(), user.getUserId());
            relay(client.put(consentPath(consentId), rejection.getBody(), rejection.getGroupId()), response);
        } catch (ConsentApprovalBuilder.InvalidConsentStateException e) {
            HttpUtil.sendError(response, HttpServletResponse.SC_CONFLICT,
                    "INVALID_CONSENT_STATE", "This consent can no longer be rejected.");
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /** {@code POST /me/consents/{id}/revoke} — withdraw a consent already given. */
    private void revoke(HttpServletRequest request, HttpServletResponse response, String consentId)
            throws IOException {

        AuthenticatedUser user = requireScope(request, response, scopes().consentsWriteSelf());
        if (user == null) {
            return;
        }
        ConsentServerClient client = client(user);
        try {
            ConsentServerClient.Result current = client.get(consentPath(consentId));
            if (current.getStatus() != HttpServletResponse.SC_OK) {
                relay(current, response);
                return;
            }
            String groupId = ownedGroupId(current.getBody(), user.getUserId());
            if (groupId == null) {
                notFound(response, consentId, user);
                return;
            }
            ObjectNode payload = HttpUtil.mapper().createObjectNode();
            payload.put("actionBy", user.getUserId());
            relay(client.post(consentPath(consentId) + "/revoke", payload.toString(), groupId), response);
        } catch (ConsentServerClient.UpstreamUnavailableException e) {
            sendUpstreamUnavailable(response, e);
        }
    }

    /**
     * Returns the consent's group when the user holds an authorization on it,
     * or null when they do not.
     *
     * <p>The group is read from the record the server returned, never from the
     * caller: it is what the Consent Server authorises a write against.
     */
    static String ownedGroupId(String body, String userId) {

        try {
            JsonNode consent = HttpUtil.mapper().readTree(body);
            for (JsonNode authorization : consent.path("authorizations")) {
                if (TextUtil.equalsFolded(authorization.path("userId").asText("").trim(), userId.trim())) {
                    return consent.path("groupId").asText("");
                }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    private ConsentServerClient client(AuthenticatedUser user) {

        return new ConsentServerClient(config(), user.getOrganizationId());
    }

    private static String consentPath(String consentId) {

        return ConsentServerClient.CONSENTS_API + "/" + encode(consentId);
    }

    private void notFound(HttpServletResponse response, String consentId, AuthenticatedUser user)
            throws IOException {

        LOG.warn("Consent " + LogUtil.sanitize(consentId) + " does not belong to the caller");
        HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                "CONSENT_NOT_FOUND", "Consent not found.");
    }

    private static String encode(String value) {

        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

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
