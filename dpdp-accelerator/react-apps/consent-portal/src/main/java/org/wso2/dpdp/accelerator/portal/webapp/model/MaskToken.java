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

package org.wso2.dpdp.accelerator.portal.webapp.model;

import java.time.Instant;
import java.util.Set;

/**
 * A verified impersonation token.
 *
 * <p>Every field here has survived signature, issuer, audience and expiry
 * validation — nothing on this object is derived from an unverified source.
 */
public final class MaskToken {

    private final String owner;
    private final String nominee;
    private final Set<String> scopes;
    private final Instant expiry;
    private final String organizationId;

    public MaskToken(String owner, String nominee, Set<String> scopes, Instant expiry, String organizationId) {

        this.owner = owner;
        this.nominee = nominee;
        this.scopes = Set.copyOf(scopes);
        this.expiry = expiry;
        this.organizationId = organizationId;
    }

    /** The {@code sub} claim: the data principal being acted for. */
    public String getOwner() {

        return owner;
    }

    /**
     * The {@code act.sub} (or {@code may_act.sub}) claim: the real human
     * performing the action. Always populated — a token without it is rejected,
     * never downgraded.
     */
    public String getNominee() {

        return nominee;
    }

    /**
     * The token's {@code scope} claim, already narrowed by the Identity Server
     * to what the owner granted this nominee.
     */
    public Set<String> getScopes() {

        return scopes;
    }

    public Instant getExpiry() {

        return expiry;
    }

    /**
     * The owner's tenant, taken from the token rather than from the caller.
     * Upstream is multi-tenant on this value, so it must never be
     * client-supplied.
     */
    public String getOrganizationId() {

        return organizationId;
    }

    public boolean hasScope(String scope) {

        return scopes.contains(scope);
    }
}
