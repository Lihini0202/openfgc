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

package org.wso2.dpdp.accelerator.portal.webapp.util;

import java.util.List;

/**
 * The canonical portal authorization scopes, resolved against the configured
 * scope prefix.
 *
 * <p>Delegation rides on {@code :self}. A nominee's impersonation token carries
 * the token subject's own scopes with {@code sub} set to the owner, so
 * {@code :self} resolves to the owner's data. No {@code :any} scope is ever
 * delegatable, which is what bounds a nominee to the owner's own records and
 * nothing wider.
 */
public final class PortalScopes {

    private final String prefix;

    public PortalScopes(PortalConfig config) {

        this.prefix = config.getScopePrefix();
    }

    public String consentsReadSelf() {

        return prefix + "consents:read:self";
    }

    public String consentsWriteSelf() {

        return prefix + "consents:write:self";
    }

    /**
     * Separate from write because approving and revoking are opposite acts.
     * Revoking withdraws processing already chosen; approving authorises new
     * processing. A grant of one must not silently confer the other.
     */
    public String consentsApproveSelf() {

        return prefix + "consents:approve:self";
    }

    /**
     * Administrative power is simply {@code :any} on the resource being
     * administered, which keeps privileges separable: a compliance officer can
     * hold {@code consents:read:any} without any catalog write.
     */
    public String consentsReadAny() {

        return prefix + "consents:read:any";
    }

    public String consentsWriteAny() {

        return prefix + "consents:write:any";
    }

    public String elementsRead() {

        return prefix + "elements:read";
    }

    public String elementsWrite() {

        return prefix + "elements:write";
    }

    public String purposesRead() {

        return prefix + "purposes:read";
    }

    public String purposesWrite() {

        return prefix + "purposes:write";
    }

    public String profileReadSelf() {

        return prefix + "profile:read:self";
    }

    public String profileWriteSelf() {

        return prefix + "profile:write:self";
    }

    public String profileDeleteSelf() {

        return prefix + "profile:delete:self";
    }

    /**
     * Administrative power is simply {@code :any} on the resource being
     * administered, which keeps privileges separable: a compliance officer can
     * hold {@code profile:write:any} without {@code consents:write:any}.
     */
    public String profileReadAny() {

        return prefix + "profile:read:any";
    }

    /**
     * The only scopes an impersonation token may carry. They are requested at
     * mint time and then trimmed by the nomination validator to whatever the
     * owner actually granted that nominee.
     *
     * <p>Nothing administrative appears here, and nothing that would let a
     * nominee manage nominations: delegation must not be transitive.
     */
    public List<String> delegatable() {

        return List.of(
                consentsReadSelf(), consentsWriteSelf(), consentsApproveSelf(),
                profileReadSelf(), profileWriteSelf(), profileDeleteSelf());
    }
}
