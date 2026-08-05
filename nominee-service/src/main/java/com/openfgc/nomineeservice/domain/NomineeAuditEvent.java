package com.openfgc.nomineeservice.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * One append-only record of something that happened to a nomination. Rows are
 * never updated or deleted once written.
 *
 * <p>Rows are hash-chained: each row's hash covers its own fields plus the
 * previous row's hash, so altering or removing a row invalidates every row after
 * it. This makes tampering detectable rather than impossible, which is why the
 * chaining fields are set only by {@link #chainTo} and never exposed as setters:
 * a record cannot be given a hash that does not match its own contents.
 */
@Entity
@Table(name = "nominee_audit_events")
public class NomineeAuditEvent {

    public enum EventType {
        NOMINATED,
        PERMISSIONS_CHANGED,
        ACCEPTED,
        ACTIVATED,
        DEACTIVATED,
        REMOVED,
        SESSION_STARTED,
        SESSION_DENIED,
        ACTION_PERFORMED,
        ACTION_DENIED
    }

    @Id
    private String id = UUID.randomUUID().toString();

    private String nominationId;
    private String ownerId;
    private String nomineeId;

    @Enumerated(EnumType.STRING)
    private EventType eventType;

    /** Free-form context, such as a ticket reference or a deactivation reason. */
    private String detail;

    private Instant occurredAt = Instant.now();

    /** Position in the hash chain, assigned when the row is appended. */
    private long sequence;

    /** Hash of the previous row in the chain, or "" for the first row. */
    private String previousHash;

    /** SHA-256 of this row's fields plus previousHash. */
    private String hash;

    protected NomineeAuditEvent() {
        // JPA
    }

    public NomineeAuditEvent(String nominationId, String ownerId, String nomineeId,
                              EventType eventType, String detail) {
        this.nominationId = nominationId;
        this.ownerId = ownerId;
        this.nomineeId = nomineeId;
        this.eventType = eventType;
        this.detail = detail;
    }

    public String getId() {
        return id;
    }

    public String getNominationId() {
        return nominationId;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public String getNomineeId() {
        return nomineeId;
    }

    public EventType getEventType() {
        return eventType;
    }

    public String getDetail() {
        return detail;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public long getSequence() {
        return sequence;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String getHash() {
        return hash;
    }

    /**
     * Links this record to the end of the chain, deriving its position and hash
     * from {@code previous}. Passing null starts a new chain.
     */
    public void chainTo(NomineeAuditEvent previous) {
        this.sequence = previous == null ? 0 : previous.sequence + 1;
        this.previousHash = previous == null ? "" : previous.hash;
        this.hash = computeHash();
    }

    /** Whether the stored hash still matches this record's contents. */
    public boolean hasIntactHash() {
        return computeHash().equals(hash);
    }

    private String computeHash() {
        String canonical = String.join("|",
                nullToEmpty(previousHash),
                String.valueOf(sequence),
                id,
                nullToEmpty(nominationId),
                nullToEmpty(ownerId),
                nullToEmpty(nomineeId),
                eventType.name(),
                nullToEmpty(detail),
                occurredAt.toString());
        return sha256Hex(canonical);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
