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

import org.wso2.dpdp.accelerator.portal.webapp.client.ScimDirectoryClient;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;
import org.wso2.dpdp.accelerator.portal.webapp.util.PortalConstants;

import java.io.IOException;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@code GET /nominees/lookup?email=} — resolves a nominee candidate's email to
 * their user ID.
 *
 * <p>Any authenticated user may call this: Nominee Service requires the nominee's
 * ID upfront when a nomination is submitted and has no directory access of its
 * own, so without this the owner would have to know an internal identifier.
 */
@WebServlet(urlPatterns = "/nominees/lookup")
public class NomineeLookupServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (requireScope(request, response, scopes().profileReadSelf()) == null) {
            return;
        }

        String email = request.getParameter("email");
        email = email == null ? "" : email.trim();
        if (email.isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "email is required");
            return;
        }

        try {
            HttpUtil.sendJson(response, HttpServletResponse.SC_OK, directory().findByEmail(email));
        } catch (ScimDirectoryClient.UserNotFoundException e) {
            HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                    PortalConstants.ERROR_NOT_FOUND, "no registered user with that email");
        } catch (ScimDirectoryClient.DirectoryUnavailableException e) {
            sendDirectoryUnavailable(response);
        }
    }
}
