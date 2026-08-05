package com.openfgc.nomineeservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.openfgc.nomineeservice.domain.Nomination;
import com.openfgc.nomineeservice.domain.NominationStatus;
import com.openfgc.nomineeservice.domain.NomineePermission;
import com.openfgc.nomineeservice.repository.NominationRepository;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Covers the behaviour DPDP Rule 14(4) requires: an owner may nominate one or
 * more individuals, each with an independent permission set and lifecycle.
 */
@SpringBootTest
@Transactional
class NominationServiceTest {

    private static final String OWNER = "owner-1";
    private static final String ALICE = "nominee-alice";
    private static final String BOB = "nominee-bob";
    private static final String CAROL = "nominee-carol";

    @Autowired
    private NominationService service;

    @Autowired
    private NominationRepository nominations;

    private Nomination nominate(String nomineeId, NomineePermission... permissions) {
        return service.nominate(OWNER, nomineeId, nomineeId + "@example.com", "NIC-" + nomineeId,
                Set.of(permissions));
    }

    // The core requirement: more than two, each independent.
    @Test
    void ownerCanNominateManyIndividuals() {
        nominate(ALICE, NomineePermission.CONSENT_VIEW);
        nominate(BOB, NomineePermission.CONSENT_VIEW, NomineePermission.CONSENT_REVOKE);
        nominate(CAROL, NomineePermission.CONSENT_VIEW);

        List<Nomination> all = service.getByOwnerId(OWNER);

        assertThat(all).hasSize(3);
        assertThat(all).extracting(Nomination::getNomineeId)
                .containsExactlyInAnyOrder(ALICE, BOB, CAROL);
    }

    // Nominating is additive: an owner's existing nominees keep their own
    // permissions and status when another is added.
    @Test
    void addingANomineeDoesNotRemoveExistingOnes() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);

        nominate(BOB, NomineePermission.CONSENT_REVOKE);

        assertThat(nominations.findById(alice.getId())).isPresent();
        assertThat(service.getByOwnerId(OWNER)).hasSize(2);
    }

    @Test
    void eachNomineeCarriesItsOwnPermissions() {
        nominate(ALICE, NomineePermission.CONSENT_VIEW);
        nominate(BOB, NomineePermission.CONSENT_VIEW, NomineePermission.CONSENT_REVOKE);

        Nomination alice = service.getByOwnerId(OWNER).stream()
                .filter(n -> n.getNomineeId().equals(ALICE)).findFirst().orElseThrow();
        Nomination bob = service.getByOwnerId(OWNER).stream()
                .filter(n -> n.getNomineeId().equals(BOB)).findFirst().orElseThrow();

        assertThat(alice.getPermissions()).containsExactly(NomineePermission.CONSENT_VIEW);
        assertThat(bob.getPermissions()).containsExactlyInAnyOrder(
                NomineePermission.CONSENT_VIEW, NomineePermission.CONSENT_REVOKE);
    }

    @Test
    void permissionsCanBeChangedForOneNomineeWithoutAffectingOthers() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);
        Nomination bob = nominate(BOB, NomineePermission.CONSENT_VIEW);

        service.updatePermissions(alice.getId(), OWNER,
                Set.of(NomineePermission.CONSENT_VIEW, NomineePermission.CONSENT_REVOKE));

        assertThat(nominations.findById(alice.getId()).orElseThrow().getPermissions())
                .containsExactlyInAnyOrder(NomineePermission.CONSENT_VIEW,
                        NomineePermission.CONSENT_REVOKE);
        assertThat(nominations.findById(bob.getId()).orElseThrow().getPermissions())
                .containsExactly(NomineePermission.CONSENT_VIEW);
    }

    @Test
    void removingOneNomineeLeavesTheOthers() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);
        nominate(BOB, NomineePermission.CONSENT_VIEW);
        nominate(CAROL, NomineePermission.CONSENT_VIEW);

        service.removeNomination(alice.getId(), OWNER);

        assertThat(service.getByOwnerId(OWNER)).hasSize(2);
        assertThat(service.getByOwnerId(OWNER)).extracting(Nomination::getNomineeId)
                .containsExactlyInAnyOrder(BOB, CAROL);
    }

    @Test
    void activatingOneNomineeDoesNotActivateOthers() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);
        Nomination bob = nominate(BOB, NomineePermission.CONSENT_VIEW);
        service.accept(alice.getId(), ALICE);
        service.accept(bob.getId(), BOB);

        service.activate(alice.getId(), "admin-1", "TICKET-1");

        assertThat(nominations.findById(alice.getId()).orElseThrow().getStatus())
                .isEqualTo(NominationStatus.ACTIVE);
        assertThat(nominations.findById(bob.getId()).orElseThrow().getStatus())
                .isEqualTo(NominationStatus.ACCEPTED);
    }

    @Test
    void sameNomineeCannotBeNominatedTwiceByTheSameOwner() {
        nominate(ALICE, NomineePermission.CONSENT_VIEW);

        assertThatThrownBy(() -> nominate(ALICE, NomineePermission.CONSENT_REVOKE))
                .isInstanceOf(DuplicateNominationException.class);
    }

    @Test
    void theSamePersonMayBeNominatedByDifferentOwners() {
        nominate(ALICE, NomineePermission.CONSENT_VIEW);

        service.nominate("owner-2", ALICE, "alice@example.com", "NIC", Set.of(NomineePermission.CONSENT_VIEW));

        assertThat(service.getByNomineeId(ALICE)).hasSize(2);
    }

    // Holding the right scope is not enough - the caller must be the nominee.
    @Test
    void onlyTheNamedNomineeMayAccept() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);

        assertThatThrownBy(() -> service.accept(alice.getId(), BOB))
                .isInstanceOf(NotAuthorizedException.class);

        assertThat(nominations.findById(alice.getId()).orElseThrow().getStatus())
                .isEqualTo(NominationStatus.PENDING);
    }

    // A known nomination id is not by itself authority to change it.
    @Test
    void anotherOwnerCannotEditOrRemoveSomeoneElsesNomination() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);

        assertThatThrownBy(() -> service.updatePermissions(alice.getId(), "owner-2",
                Set.of(NomineePermission.CONSENT_REVOKE)))
                .isInstanceOf(NominationNotFoundException.class);
        assertThatThrownBy(() -> service.removeNomination(alice.getId(), "owner-2"))
                .isInstanceOf(NominationNotFoundException.class);

        assertThat(nominations.findById(alice.getId())).isPresent();
    }

    @Test
    void anOwnerWithNoNomineesGetsAnEmptyList() {
        assertThat(service.getByOwnerId("owner-with-nothing")).isEmpty();
    }

    // A caller holding a nomination must not be able to widen its own grant by
    // mutating the returned collection.
    @Test
    void grantedPermissionsCannotBeModifiedThroughTheGetter() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);

        assertThatThrownBy(() -> alice.getPermissions().add(NomineePermission.CONSENT_REVOKE))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(alice.getPermissions()).containsExactly(NomineePermission.CONSENT_VIEW);
    }

    // The gate is the single answer both IS and the BFF act on, so an inactive
    // nomination must report no permissions rather than its stored set.
    @Test
    void theGateReportsNoPermissionsUntilActivated() {
        Nomination alice = nominate(ALICE, NomineePermission.CONSENT_VIEW);

        GateDecision pending = service.gateDecision(OWNER, ALICE);
        assertThat(pending.active()).isFalse();
        assertThat(pending.permissions()).isEmpty();

        service.accept(alice.getId(), ALICE);
        service.activate(alice.getId(), "admin-1", "TICKET-1");

        GateDecision active = service.gateDecision(OWNER, ALICE);
        assertThat(active.active()).isTrue();
        assertThat(active.grants(NomineePermission.CONSENT_VIEW)).isTrue();
        assertThat(active.grants(NomineePermission.CONSENT_REVOKE)).isFalse();

        service.deactivate(alice.getId(), "admin-1", "no longer required");
        assertThat(service.gateDecision(OWNER, ALICE).permissions()).isEmpty();
    }
}
