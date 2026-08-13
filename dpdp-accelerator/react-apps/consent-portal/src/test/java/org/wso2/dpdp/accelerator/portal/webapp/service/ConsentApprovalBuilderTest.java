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

import com.fasterxml.jackson.databind.JsonNode;
import org.testng.annotations.Test;
import org.wso2.dpdp.accelerator.portal.webapp.util.HttpUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * The approval and rejection payloads decide what a person is recorded as having
 * agreed to. The rules worth pinning are mostly about what must NOT change: a
 * mandatory element is approved regardless of what was selected, an unselected
 * optional element stays unapproved, and another party's authorization is left
 * exactly as it was.
 */
public class ConsentApprovalBuilderTest {

    /** A builder whose catalog answers from memory rather than over the network. */
    private static final class StubCatalog extends ConsentApprovalBuilder {

        private final String catalogJson;

        StubCatalog(String catalogJson) {

            super(null);
            this.catalogJson = catalogJson;
        }

        @Override
        protected List<JsonNode> fetchPurposePage(String purposeName, String clientId) {

            try {
                List<JsonNode> out = new ArrayList<>();
                HttpUtil.mapper().readTree(catalogJson).forEach(out::add);
                return out;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final String CATALOG =
            "[{'name':'marketing','clientId':'client-1','elements':["
            + "{'name':'email','isMandatory':true},"
            + "{'name':'phone','isMandatory':false},"
            + "{'name':'post','isMandatory':false}]}]";

    private static final String CONSENT =
            "{'status':'CREATED','type':'marketing','clientId':'client-1','groupId':'group-9',"
            + "'purposes':[{'name':'marketing','elements':["
            + "{'name':'email'},{'name':'phone'},{'name':'post'}]}],"
            + "'authorizations':["
            + "{'userId':'owner-1','type':'authorisation','status':'CREATED'},"
            + "{'userId':'someone-else','type':'authorisation','status':'APPROVED'}]}";

    /** The fixtures above use single quotes for readability; JSON needs double. */
    private static String json(String fixture) {

        return fixture.replace('\'', '"');
    }

    private static JsonNode parse(String value) throws IOException {

        return HttpUtil.mapper().readTree(value);
    }

    private static ConsentApprovalBuilder builder() {

        return new StubCatalog(json(CATALOG));
    }

    private static JsonNode elementNamed(JsonNode payload, String name) {

        for (JsonNode element : payload.path("purposes").get(0).path("elements")) {
            if (name.equals(element.path("name").asText())) {
                return element;
            }
        }
        throw new IllegalStateException("no element named " + name);
    }

    @Test
    public void approvesMandatoryElementsEvenWhenNotSelected() throws Exception {

        ConsentApprovalBuilder.Payload result = builder().build(json(CONSENT), "[]", "owner-1");
        JsonNode payload = parse(result.getBody());

        assertTrue(elementNamed(payload, "email").path("isUserApproved").asBoolean(),
                "a mandatory element belongs to the consent whether or not it was ticked");
        assertTrue(elementNamed(payload, "email").path("isMandatory").asBoolean());
    }

    @Test
    public void leavesUnselectedOptionalElementsUnapproved() throws Exception {

        String selection = json("[{'purposeName':'marketing','elementName':'phone'}]");
        JsonNode payload = parse(builder().build(json(CONSENT), selection, "owner-1").getBody());

        assertTrue(elementNamed(payload, "phone").path("isUserApproved").asBoolean());
        assertFalse(elementNamed(payload, "post").path("isUserApproved").asBoolean(),
                "an optional element nobody selected must not be approved");
    }

    @Test
    public void rejectsASelectionTheConsentDoesNotOffer() throws Exception {

        String selection = json("[{'purposeName':'marketing','elementName':'not-on-this-consent'}]");
        try {
            builder().build(json(CONSENT), selection, "owner-1");
            fail("a selection naming an unknown element must not be silently ignored");
        } catch (ConsentApprovalBuilder.InvalidSelectionException expected) {
            // The caller asked for something this consent cannot grant.
        }
    }

    @Test
    public void matchesSelectionsCaseSensitively() throws Exception {

        String selection = json("[{'purposeName':'Marketing','elementName':'phone'}]");
        try {
            builder().build(json(CONSENT), selection, "owner-1");
            fail("purpose and element names are identifiers, not free text");
        } catch (ConsentApprovalBuilder.InvalidSelectionException expected) {
            // Folding case would approve an element the caller did not name.
        }
    }

    @Test
    public void recordsTheApprovalAgainstTheOwnerAndCarriesTheGroup() throws Exception {

        ConsentApprovalBuilder.Payload result = builder().build(json(CONSENT), "[]", "owner-1");
        JsonNode payload = parse(result.getBody());

        assertEquals(result.getGroupId(), "group-9", "writes are authorised on the consent's own group");

        boolean ownerApproved = false;
        for (JsonNode authorization : payload.path("authorizations")) {
            if ("owner-1".equals(authorization.path("userId").asText())) {
                assertEquals(authorization.path("status").asText(), "APPROVED");
                ownerApproved = true;
            }
        }
        assertTrue(ownerApproved, "the owner's authorization is the one that changes");
    }

    @Test
    public void leavesOtherPeoplesAuthorizationsAlone() throws Exception {

        JsonNode payload = parse(builder().build(json(CONSENT), "[]", "owner-1").getBody());

        for (JsonNode authorization : payload.path("authorizations")) {
            if ("someone-else".equals(authorization.path("userId").asText())) {
                assertEquals(authorization.path("status").asText(), "APPROVED",
                        "another party's decision is not this caller's to change");
            }
        }
    }

    @Test
    public void rejectionFlipsOnlyTheCallersAuthorization() throws Exception {

        ConsentApprovalBuilder.Payload result = builder().buildRejection(json(CONSENT), "owner-1");
        JsonNode payload = parse(result.getBody());

        assertEquals(result.getGroupId(), "group-9");
        for (JsonNode authorization : payload.path("authorizations")) {
            String user = authorization.path("userId").asText();
            assertEquals(authorization.path("status").asText(),
                    "owner-1".equals(user) ? "REJECTED" : "APPROVED", "status for " + user);
        }
    }

    @Test
    public void refusesToRejectAConsentThatIsNoLongerPending() throws Exception {

        String decided = json(CONSENT).replace("\"status\":\"CREATED\"", "\"status\":\"ACTIVE\"");
        try {
            builder().buildRejection(decided, "owner-1");
            fail("only a pending consent can be rejected");
        } catch (ConsentApprovalBuilder.InvalidConsentStateException expected) {
            // An already-decided consent is not re-decidable through this path.
        }
    }

    @Test
    public void refusesToRejectOnBehalfOfSomebodyHoldingNoAuthorization() throws Exception {

        try {
            builder().buildRejection(json(CONSENT), "a-stranger");
            fail("a caller holding no authorization has nothing to reject");
        } catch (ConsentApprovalBuilder.InvalidConsentStateException expected) {
            // There is no authorization of theirs to flip.
        }
    }
}
