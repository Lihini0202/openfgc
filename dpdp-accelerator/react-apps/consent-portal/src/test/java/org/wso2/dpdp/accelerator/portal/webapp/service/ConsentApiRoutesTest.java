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

package org.wso2.dpdp.accelerator.portal.webapp.service;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * The allowlist is the whole of what a browser can reach through the catalog
 * proxy, so what it refuses matters as much as what it permits.
 */
public class ConsentApiRoutesTest {

    @DataProvider(name = "allowed")
    public Object[][] allowed() {

        return new Object[][] {
            {"GET", "/consents", ConsentApiRoutes.Scope.CONSENTS_READ_ANY},
            {"POST", "/consents", ConsentApiRoutes.Scope.CONSENTS_WRITE_ANY},
            {"GET", "/consents/attributes", ConsentApiRoutes.Scope.CONSENTS_READ_ANY},
            {"GET", "/consents/abc-123", ConsentApiRoutes.Scope.CONSENTS_READ_ANY},
            {"PUT", "/consents/abc-123", ConsentApiRoutes.Scope.CONSENTS_WRITE_ANY},
            {"POST", "/consents/abc-123/revoke", ConsentApiRoutes.Scope.CONSENTS_WRITE_ANY},
            {"GET", "/consents/abc/authorizations/xyz", ConsentApiRoutes.Scope.CONSENTS_READ_ANY},
            {"GET", "/consent-purposes", ConsentApiRoutes.Scope.PURPOSES_READ},
            {"DELETE", "/consent-purposes/p1/versions/2", ConsentApiRoutes.Scope.PURPOSES_WRITE},
            {"GET", "/consent-elements/e1/versions", ConsentApiRoutes.Scope.ELEMENTS_READ},
            {"POST", "/consent-elements/e1/versions", ConsentApiRoutes.Scope.ELEMENTS_WRITE},
        };
    }

    @Test(dataProvider = "allowed")
    public void permitsAllowlistedOperationsWithTheirScope(String method, String path,
                                                           ConsentApiRoutes.Scope expected) {

        ConsentApiRoutes.Match match = ConsentApiRoutes.match(method, path);

        assertEquals(match.getDecision(), ConsentApiRoutes.Decision.ALLOWED, method + " " + path);
        assertEquals(match.getScope(), expected, "scope for " + method + " " + path);
    }

    /**
     * A write must never be permitted by a read entry: the catalog is
     * administrative, and read and write are separately granted.
     */
    @DataProvider(name = "wrongMethod")
    public Object[][] wrongMethod() {

        return new Object[][] {
            {"DELETE", "/consents"},
            {"PUT", "/consent-purposes"},
            {"POST", "/consents/abc-123"},
            {"DELETE", "/consent-elements/e1/versions"},
        };
    }

    @Test(dataProvider = "wrongMethod")
    public void reportsAKnownPathUnderAnUnsupportedMethodAsMethodNotAllowed(String method, String path) {

        ConsentApiRoutes.Match match = ConsentApiRoutes.match(method, path);

        assertEquals(match.getDecision(), ConsentApiRoutes.Decision.METHOD_NOT_ALLOWED, method + " " + path);
        assertNull(match.getScope(), "a refused request carries no scope");
    }

    @DataProvider(name = "unknown")
    public Object[][] unknown() {

        return new Object[][] {
            {"GET", "/consents/abc/unknown-sub-resource"},
            {"GET", "/not-a-resource"},
            {"GET", "/consents/abc/authorizations/xyz/extra"},
            {"GET", "/"},
            {"GET", ""},
            {"GET", "/consents//revoke"},
        };
    }

    @Test(dataProvider = "unknown")
    public void refusesAnythingNotOnTheList(String method, String path) {

        ConsentApiRoutes.Match match = ConsentApiRoutes.match(method, path);

        assertEquals(match.getDecision(), ConsentApiRoutes.Decision.UNKNOWN_ROUTE, method + " " + path);
    }

    @Test
    public void treatsATrailingSlashAsTheSameRoute() {

        assertEquals(ConsentApiRoutes.match("GET", "/consents/").getDecision(),
                ConsentApiRoutes.Decision.ALLOWED);
    }

    @Test
    public void doesNotLetAWildcardSwallowAnExtraSegment() {

        // "consents/*" must not match "consents/a/b": a wildcard stands for one
        // segment, not for the rest of the path.
        assertEquals(ConsentApiRoutes.match("PUT", "/consents/a/b").getDecision(),
                ConsentApiRoutes.Decision.UNKNOWN_ROUTE);
    }
}
