package com.openfgc.nomineeservice.service;

import com.openfgc.nomineeservice.domain.Nomination;
import com.openfgc.nomineeservice.domain.NominationStatus;
import com.openfgc.nomineeservice.domain.NomineeAuditEvent.EventType;
import com.openfgc.nomineeservice.domain.NomineePermission;
import com.openfgc.nomineeservice.repository.NominationRepository;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Owns the nomination lifecycle: nominate, accept, activate, deactivate.
 *
 * <p>An owner may nominate any number of individuals. Every mutation below is
 * addressed to one specific nomination, so adding, editing or removing one
 * nominee never disturbs the others.
 */
@Service
public class NominationService {

    private final NominationRepository nominations;
    private final NomineeAuditService auditService;

    public NominationService(NominationRepository nominations, NomineeAuditService auditService) {
        this.nominations = nominations;
        this.auditService = auditService;
    }

    /**
     * Adds a nominee to this owner's existing nominations. The same person may
     * not be nominated twice by the same owner.
     */
    @Transactional
    public Nomination nominate(String ownerId, String nomineeId, String nomineeEmail, String nomineeNic,
                                Set<NomineePermission> permissions) {
        if (nominations.existsByOwnerIdAndNomineeId(ownerId, nomineeId)) {
            throw new DuplicateNominationException(ownerId, nomineeId);
        }

        Nomination nomination = new Nomination(ownerId, nomineeId, nomineeEmail, nomineeNic,
                NomineePermission.expand(permissions));
        nominations.save(nomination);
        audit(nomination, EventType.NOMINATED, "permissions=" + permissions);
        return nomination;
    }

    /**
     * Replaces the permissions granted to one nominee.
     *
     * <p>Scoped to the owner: a caller can only edit a nomination they made, so a
     * known nomination id is not by itself authority to change it.
     */
    @Transactional
    public Nomination updatePermissions(String nominationId, String ownerId,
                                         Set<NomineePermission> permissions) {
        Nomination nomination = getOwned(nominationId, ownerId);
        Set<NomineePermission> previous = Set.copyOf(nomination.getPermissions());
        nomination.setPermissions(NomineePermission.expand(permissions));
        audit(nomination, EventType.PERMISSIONS_CHANGED, "from=" + previous + " to=" + permissions);
        return nomination;
    }

    /**
     * The nominee accepts. The caller must be the nominee named on this
     * nomination - holding the right scope is not enough, or any authenticated
     * user could accept someone else's nomination by id.
     */
    @Transactional
    public Nomination accept(String nominationId, String callerId) {
        Nomination nomination = get(nominationId);
        if (!nomination.getNomineeId().equals(callerId)) {
            throw new NotAuthorizedException("Only the nominated user may accept this nomination");
        }
        nomination.accept();
        audit(nomination, EventType.ACCEPTED, null);
        return nomination;
    }

    @Transactional
    public Nomination activate(String nominationId, String adminId, String ticketReference) {
        Nomination nomination = get(nominationId);
        nomination.activate(adminId, ticketReference);
        audit(nomination, EventType.ACTIVATED, "admin=" + adminId + " ticket=" + ticketReference);
        return nomination;
    }

    @Transactional
    public Nomination deactivate(String nominationId, String adminId, String reason) {
        Nomination nomination = get(nominationId);
        nomination.deactivate(adminId, reason);
        audit(nomination, EventType.DEACTIVATED, "admin=" + adminId + " reason=" + reason);
        return nomination;
    }

    /** Removes one nominee, leaving the owner's other nominations untouched. */
    @Transactional
    public void removeNomination(String nominationId, String ownerId) {
        Nomination nomination = getOwned(nominationId, ownerId);
        audit(nomination, EventType.REMOVED, null);
        nominations.delete(nomination);
    }

    /**
     * Loads a nomination and confirms it belongs to this owner. Returning
     * "not found" rather than "forbidden" for someone else's nomination avoids
     * confirming that an id exists.
     */
    private Nomination getOwned(String nominationId, String ownerId) {
        Nomination nomination = get(nominationId);
        if (!nomination.getOwnerId().equals(ownerId)) {
            throw new NominationNotFoundException(nominationId);
        }
        return nomination;
    }

    public Nomination get(String nominationId) {
        return nominations.findById(nominationId)
                .orElseThrow(() -> new NominationNotFoundException(nominationId));
    }

    /** Every nomination this owner has made. May be empty. */
    public List<Nomination> getByOwnerId(String ownerId) {
        return nominations.findByOwnerId(ownerId);
    }

    public List<Nomination> getByNomineeId(String nomineeId) {
        return nominations.findByNomineeId(nomineeId);
    }

    /** Nominations accepted by the nominee but not yet activated - the admin review queue. */
    public List<Nomination> getPendingActivation() {
        return nominations.findByStatus(NominationStatus.ACCEPTED);
    }

    /**
     * Resolves what one nominee may currently do on one owner's behalf.
     *
     * <p>This is read on every acting request rather than only at token issue, so
     * removing a permission or deactivating a nomination takes effect on the next
     * request instead of when the token expires.
     */
    @Transactional(readOnly = true)
    public GateDecision gateDecision(String ownerId, String nomineeId) {
        return nominations.findByOwnerIdAndNomineeId(ownerId, nomineeId)
                .filter(nomination -> nomination.getStatus() == NominationStatus.ACTIVE)
                .map(nomination -> GateDecision.allowed(nomination.getPermissions()))
                .orElseGet(GateDecision::denied);
    }

    void audit(Nomination nomination, EventType type, String detail) {
        auditService.record(nomination.getId(), nomination.getOwnerId(), nomination.getNomineeId(), type, detail);
    }
}
