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

import java.util.List;
import java.util.Set;

/**
 * The operations the portal may reach on the Consent Server, and the scope each
 * one demands.
 *
 * <p>Held apart from the servlet that enforces it so the policy can be read, and
 * tested, on its own: this table is the whole of what a browser can reach
 * through the catalog proxy, and a mistake in it is not visible by reading the
 * servlet. Anything absent is refused, so a new upstream operation is a
 * deliberate entry here rather than something a path happens to allow.
 */
public final class ConsentApiRoutes {

    /** Which scope an operation demands, resolved by the caller against its prefix. */
    public enum Scope { CONSENTS_READ_ANY, CONSENTS_WRITE_ANY, ELEMENTS_READ, ELEMENTS_WRITE,
        PURPOSES_READ, PURPOSES_WRITE }

    /** The outcome of matching a request against the table. */
    public enum Decision { ALLOWED, METHOD_NOT_ALLOWED, UNKNOWN_ROUTE }

    /** A matched request: what was decided, and the scope it requires when allowed. */
    public static final class Match {

        private final Decision decision;
        private final Scope scope;

        Match(Decision decision, Scope scope) {

            this.decision = decision;
            this.scope = scope;
        }

        public Decision getDecision() {

            return decision;
        }

        /** The required scope, or null unless the decision is ALLOWED. */
        public Scope getScope() {

            return scope;
        }
    }

    private static final class Route {

        private final String[] parts;
        private final Set<String> methods;
        private final Scope scope;

        Route(String template, Set<String> methods, Scope scope) {

            this.parts = template.split("/");
            this.methods = methods;
            this.scope = scope;
        }

        boolean matchesPath(String[] path) {

            if (path.length != parts.length) {
                return false;
            }
            for (int i = 0; i < parts.length; i++) {
                if (path[i].isEmpty() || (!"*".equals(parts[i]) && !parts[i].equals(path[i]))) {
                    return false;
                }
            }
            return true;
        }
    }

    private static final Set<String> GET = Set.of("GET");
    private static final Set<String> POST = Set.of("POST");
    private static final Set<String> PUT = Set.of("PUT");
    private static final Set<String> DELETE = Set.of("DELETE");

    private static final List<Route> ROUTES = List.of(
        new Route("consents", GET, Scope.CONSENTS_READ_ANY),
        new Route("consents", POST, Scope.CONSENTS_WRITE_ANY),
        new Route("consents/attributes", GET, Scope.CONSENTS_READ_ANY),
        new Route("consents/validate", POST, Scope.CONSENTS_READ_ANY),
        new Route("consents/*", GET, Scope.CONSENTS_READ_ANY),
        new Route("consents/*", PUT, Scope.CONSENTS_WRITE_ANY),
        new Route("consents/*/history", GET, Scope.CONSENTS_READ_ANY),
        new Route("consents/*/revoke", POST, Scope.CONSENTS_WRITE_ANY),
        new Route("consents/*/authorizations", GET, Scope.CONSENTS_READ_ANY),
        new Route("consents/*/authorizations", POST, Scope.CONSENTS_WRITE_ANY),
        new Route("consents/*/authorizations/*", GET, Scope.CONSENTS_READ_ANY),
        new Route("consents/*/authorizations/*", PUT, Scope.CONSENTS_WRITE_ANY),
        new Route("consent-elements", GET, Scope.ELEMENTS_READ),
        new Route("consent-elements", POST, Scope.ELEMENTS_WRITE),
        new Route("consent-elements/*", GET, Scope.ELEMENTS_READ),
        new Route("consent-elements/*/versions", GET, Scope.ELEMENTS_READ),
        new Route("consent-elements/*/versions", POST, Scope.ELEMENTS_WRITE),
        new Route("consent-elements/*/versions/*", GET, Scope.ELEMENTS_READ),
        new Route("consent-elements/*/versions/*", DELETE, Scope.ELEMENTS_WRITE),
        new Route("consent-purposes", GET, Scope.PURPOSES_READ),
        new Route("consent-purposes", POST, Scope.PURPOSES_WRITE),
        new Route("consent-purposes/*", GET, Scope.PURPOSES_READ),
        new Route("consent-purposes/*/versions", GET, Scope.PURPOSES_READ),
        new Route("consent-purposes/*/versions", POST, Scope.PURPOSES_WRITE),
        new Route("consent-purposes/*/versions/*", GET, Scope.PURPOSES_READ),
        new Route("consent-purposes/*/versions/*", DELETE, Scope.PURPOSES_WRITE));

    private ConsentApiRoutes() {
    }

    /**
     * Resolves a request against the table.
     *
     * <p>A path that exists under a method it does not permit is reported as
     * METHOD_NOT_ALLOWED rather than as absent, so the refusal says which of the
     * two is wrong.
     *
     * @param method  the HTTP method, already upper-cased by the container
     * @param pathInfo the path below {@code /api}, with or without a leading slash
     */
    public static Match match(String method, String pathInfo) {

        String trimmed = pathInfo == null ? "" : pathInfo;
        trimmed = trimmed.startsWith("/") ? trimmed.substring(1) : trimmed;
        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        String[] segments = trimmed.isEmpty() ? new String[0] : trimmed.split("/");

        boolean pathExists = false;
        for (Route route : ROUTES) {
            if (!route.matchesPath(segments)) {
                continue;
            }
            pathExists = true;
            if (route.methods.contains(method)) {
                return new Match(Decision.ALLOWED, route.scope);
            }
        }
        return new Match(pathExists ? Decision.METHOD_NOT_ALLOWED : Decision.UNKNOWN_ROUTE, null);
    }
}
