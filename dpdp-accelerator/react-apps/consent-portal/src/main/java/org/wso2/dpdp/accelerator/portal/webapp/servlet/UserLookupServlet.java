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
 * {@code GET /users/{id}} — resolves a user ID to a display name and email.
 *
 * <p>Lets any authenticated user put a readable identity against an owner or
 * nominee ID they already hold from their own nominations, since Nominee Service
 * returns identifiers rather than names.
 */
@WebServlet(urlPatterns = "/users/*")
public class UserLookupServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (requireScope(request, response, scopes().profileReadSelf()) == null) {
            return;
        }

        String id = pathSegment(request);
        if (id.isEmpty()) {
            HttpUtil.sendError(response, HttpServletResponse.SC_BAD_REQUEST,
                    PortalConstants.ERROR_INVALID_PAYLOAD, "id is required");
            return;
        }

        try {
            HttpUtil.sendJson(response, HttpServletResponse.SC_OK, directory().getUser(id));
        } catch (ScimDirectoryClient.UserNotFoundException e) {
            HttpUtil.sendError(response, HttpServletResponse.SC_NOT_FOUND,
                    PortalConstants.ERROR_NOT_FOUND, "user not found");
        } catch (ScimDirectoryClient.DirectoryUnavailableException e) {
            sendDirectoryUnavailable(response);
        }
    }
}
