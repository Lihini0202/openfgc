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

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * The Consent Server looks a consent up by id alone and will return any record
 * in the organisation. These two predicates are the only thing standing between
 * that and one person reading - or revoking - another person's consent by
 * guessing an id, so they are pinned here including their failure modes.
 */
public class ConsentOwnershipTest {

    private static String json(String fixture) {

        return fixture.replace('\'', '"');
    }

    private static final String CONSENT = json(
            "{'groupId':'group-9','authorizations':["
            + "{'userId':'owner-1','status':'APPROVED'},"
            + "{'userId':'other-2','status':'APPROVED'}]}");

    @Test
    public void returnsTheGroupWhenTheUserHoldsAnAuthorization() {

        assertEquals(MeConsentsServlet.ownedGroupId(CONSENT, "owner-1"), "group-9");
        assertEquals(MeConsentsServlet.ownedGroupId(CONSENT, "other-2"), "group-9");
    }

    @Test
    public void returnsNullForSomebodyWithNoAuthorization() {

        assertNull(MeConsentsServlet.ownedGroupId(CONSENT, "a-stranger"),
                "holding no authorization must not yield a group to write against");
    }

    /**
     * A body this code cannot parse is never treated as the caller's. Failing
     * open here would turn an upstream hiccup into an authorization bypass.
     */
    @Test
    public void treatsAnUnparseableBodyAsNotOwned() {

        assertNull(MeConsentsServlet.ownedGroupId("not json at all", "owner-1"));
        assertNull(MeConsentsServlet.ownedGroupId("", "owner-1"));
        assertFalse(ActingConsentServlet.consentBelongsTo("not json at all", "owner-1"));
    }

    @Test
    public void treatsAConsentWithNoAuthorizationsAsNotOwned() {

        assertNull(MeConsentsServlet.ownedGroupId(json("{'groupId':'g'}"), "owner-1"));
        assertFalse(ActingConsentServlet.consentBelongsTo(json("{'authorizations':[]}"), "owner-1"));
    }

    @Test
    public void actingOwnershipAgreesWithTheFirstPartyCheck() {

        assertTrue(ActingConsentServlet.consentBelongsTo(CONSENT, "owner-1"));
        assertFalse(ActingConsentServlet.consentBelongsTo(CONSENT, "a-stranger"),
                "a nominee must not reach a consent the owner does not hold");
    }

    /**
     * An id that merely starts with, or contains, a real one is a different
     * person. This is the shape of mistake that turns into a data leak.
     */
    @Test
    public void doesNotMatchOnAPrefixOrSubstring() {

        assertNull(MeConsentsServlet.ownedGroupId(CONSENT, "owner"));
        assertNull(MeConsentsServlet.ownedGroupId(CONSENT, "owner-11"));
        assertFalse(ActingConsentServlet.consentBelongsTo(CONSENT, "owner"));
    }
}
