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
import org.wso2.dpdp.accelerator.portal.webapp.model.AuthenticatedUser;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;

import java.io.IOException;
import java.util.List;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@code GET /admin/users/search?q=} — searches portal users for the admin
 * nominee-activation screen.
 *
 * <p>Stands behind two independent barriers, checked in order: the
 * {@code profile:read:any} scope, then a live administrator role check. See
 * {@link AbstractNomineeServlet#requireAdmin}.
 */
@WebServlet(urlPatterns = "/admin/users/search")
public class AdminUserSearchServlet extends AbstractNomineeServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        AuthenticatedUser user = requireScope(request, response, scopes().profileReadAny());
        if (user == null || !requireAdmin(user, response)) {
            return;
        }

        String query = request.getParameter("q");
        query = query == null ? "" : query.trim();
        // An empty query is not an error: the search box reports no matches
        // rather than every user in the organisation.
        if (query.isEmpty()) {
            HttpUtil.sendJson(response, HttpServletResponse.SC_OK, List.of());
            return;
        }

        try {
            HttpUtil.sendJson(response, HttpServletResponse.SC_OK, directory().search(query));
        } catch (ScimDirectoryClient.DirectoryUnavailableException e) {
            sendDirectoryUnavailable(response);
        }
    }
}
