package com.openfgc.nomineeservice.service;

import com.openfgc.nomineeservice.domain.NomineeAuditEvent;
import com.openfgc.nomineeservice.domain.NomineeAuditEvent.EventType;
import com.openfgc.nomineeservice.repository.NomineeAuditEventRepository;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The only writer of audit records, appending each one to the tamper-evident
 * chain.
 *
 * <p>Appends are serialised so two concurrent writers cannot derive their
 * position from the same predecessor and produce a forked chain. The lock is
 * held per instance, so a horizontally scaled deployment needs the ordering
 * enforced by the database instead.
 */
@Service
public class NomineeAuditService {

    private final NomineeAuditEventRepository auditEvents;
    private final Object chainLock = new Object();

    public NomineeAuditService(NomineeAuditEventRepository auditEvents) {
        this.auditEvents = auditEvents;
    }

    @Transactional
    public void record(String nominationId, String ownerId, String nomineeId, EventType type, String detail) {
        synchronized (chainLock) {
            NomineeAuditEvent previous = auditEvents.findTopByOrderBySequenceDesc().orElse(null);
            NomineeAuditEvent event = new NomineeAuditEvent(nominationId, ownerId, nomineeId, type, detail);
            event.chainTo(previous);
            auditEvents.save(event);
        }
    }

    /**
     * Confirms every record still matches its own hash and still points at its
     * predecessor. Returns false on the first record that does not.
     */
    public boolean verifyChain() {
        List<NomineeAuditEvent> events = auditEvents.findAllByOrderBySequenceAsc();
        String expectedPreviousHash = "";
        for (NomineeAuditEvent event : events) {
            if (!expectedPreviousHash.equals(event.getPreviousHash()) || !event.hasIntactHash()) {
                return false;
            }
            expectedPreviousHash = event.getHash();
        }
        return true;
    }
}
