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

import org.testng.annotations.Test;
import org.wso2.dpdp.accelerator.portal.webapp.util.TextUtil;

import java.util.List;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * The scope claim is the ceiling an impersonation token was minted with, so
 * mis-parsing it either hands a nominee authority the owner never granted or
 * strips authority they did. The Identity Server may emit it either as a
 * space-delimited string or as an array, and both have to yield the same set.
 */
public class MaskScopeClaimTest {

    @Test
    public void readsASpaceDelimitedString() {

        Set<String> scopes = MaskTokenVerifier.parseScopeClaim(
                "portal:consents:read:self portal:consents:write:self");

        assertEquals(scopes, Set.of("portal:consents:read:self", "portal:consents:write:self"));
    }

    @Test
    public void readsAnArray() {

        Set<String> scopes = MaskTokenVerifier.parseScopeClaim(
                List.of("portal:consents:read:self", "portal:profile:read:self"));

        assertEquals(scopes, Set.of("portal:consents:read:self", "portal:profile:read:self"));
    }

    @Test
    public void toleratesIrregularSpacingWithoutInventingEmptyScopes() {

        Set<String> scopes = MaskTokenVerifier.parseScopeClaim("  a   b  ");

        assertEquals(scopes, Set.of("a", "b"));
    }

    /**
     * An absent or unusable claim yields no scopes rather than an error: the
     * caller then fails the scope check, which is the safe direction.
     */
    @Test
    public void yieldsNothingForAnAbsentOrUnusableClaim() {

        assertTrue(MaskTokenVerifier.parseScopeClaim(null).isEmpty());
        assertTrue(MaskTokenVerifier.parseScopeClaim("").isEmpty());
        assertTrue(MaskTokenVerifier.parseScopeClaim(42).isEmpty());
        assertTrue(MaskTokenVerifier.parseScopeClaim(List.of()).isEmpty());
    }

    @Test
    public void doesNotFoldCaseOnScopeNames() {

        Set<String> scopes = MaskTokenVerifier.parseScopeClaim("Portal:Consents:Read:Self");

        assertFalse(scopes.contains("portal:consents:read:self"),
                "a scope is an exact identifier; folding it would grant what was not minted");
    }

    /**
     * Case folding is confined to {@link TextUtil} so the rule is reviewed once.
     * It must be locale-independent: the Turkish dotless i is the usual way a
     * default-locale fold changes an identifier out from under you.
     */
    @Test
    public void foldsCaseIndependentlyOfTheDefaultLocale() {

        assertTrue(TextUtil.equalsFolded("USER@Example.COM", "user@example.com"));
        assertTrue(TextUtil.equalsFolded("Bearer ", "bearer "));
        assertFalse(TextUtil.equalsFolded("owner-1", "owner-11"));
        assertEquals(TextUtil.canonicalFold(null), "");
    }
}
