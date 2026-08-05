package com.openfgc.nomineeservice.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * One owner-to-nominee pairing: who the nominee is, what they were granted, and
 * whether the pairing is currently active. The impersonation gate reads this
 * record before any impersonation token is issued.
 *
 * <p>An owner may have any number of these. DPDP Rule 14(4) allows nominating
 * "one or more individuals", and each nomination carries its own permission set,
 * status and lifecycle, so one nominee can be view-only while another may revoke,
 * and activating or deactivating one never touches the others.
 *
 * <p>The unique constraint is on the (owner, nominee) <i>pair</i> rather than on
 * the owner: the same person may not be nominated twice by the same owner, but
 * the owner is otherwise unrestricted.
 *
 * <p>State changes go through the behaviour methods below rather than setters.
 * Each transition sets every field that transition implies, so a nomination
 * cannot be left half-way between two states.
 */
@Entity
@Table(name = "nominations",
       uniqueConstraints = @UniqueConstraint(
               name = "uq_owner_nominee",
               columnNames = {"ownerId", "nomineeId"}))
public class Nomination {

    @Id
    private String id = UUID.randomUUID().toString();

    @Column(nullable = false)
    private String ownerId;

    @Column(nullable = false)
    private String nomineeId;

    @Column(nullable = false)
    private String nomineeEmail;

    private String nomineeNic;

    @ElementCollection(targetClass = NomineePermission.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "nomination_permissions", joinColumns = @JoinColumn(name = "nomination_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "permission")
    private Set<NomineePermission> permissions = new HashSet<>();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NominationStatus status = NominationStatus.PENDING;

    private Instant nominatedAt = Instant.now();
    private Instant acceptedAt;

    private String activatedBy;
    private Instant activatedAt;
    private String activationTicket;

    private String deactivatedBy;
    private Instant deactivatedAt;
    private String deactivationReason;

    protected Nomination() {
        // JPA
    }

    public Nomination(String ownerId, String nomineeId, String nomineeEmail, String nomineeNic,
                       Set<NomineePermission> permissions) {
        this.ownerId = Objects.requireNonNull(ownerId, "ownerId");
        this.nomineeId = Objects.requireNonNull(nomineeId, "nomineeId");
        this.nomineeEmail = Objects.requireNonNull(nomineeEmail, "nomineeEmail");
        this.nomineeNic = nomineeNic;
        this.permissions = new HashSet<>(Objects.requireNonNull(permissions, "permissions"));
    }

    public String getId() {
        return id;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public String getNomineeId() {
        return nomineeId;
    }

    public String getNomineeEmail() {
        return nomineeEmail;
    }

    public String getNomineeNic() {
        return nomineeNic;
    }

    /**
     * The granted permissions, unmodifiable. Changes go through
     * {@link #setPermissions(Set)} so the owner's grant cannot be widened by a
     * caller that merely holds a reference to this nomination.
     */
    public Set<NomineePermission> getPermissions() {
        return Collections.unmodifiableSet(permissions);
    }

    /**
     * Replaces the granted permissions. The collection is mutated in place rather
     * than reassigned so JPA tracks the element-collection change.
     */
    public void setPermissions(Set<NomineePermission> replacement) {
        Objects.requireNonNull(replacement, "replacement");
        this.permissions.clear();
        this.permissions.addAll(replacement);
    }

    public boolean grants(NomineePermission permission) {
        return permissions.contains(permission);
    }

    public NominationStatus getStatus() {
        return status;
    }

    public Instant getNominatedAt() {
        return nominatedAt;
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    /**
     * Records the nominee's acceptance. Acceptance alone does not grant access:
     * the nomination stays inactive until an administrator activates it.
     */
    public void accept() {
        this.status = NominationStatus.ACCEPTED;
        this.acceptedAt = Instant.now();
    }

    public String getActivatedBy() {
        return activatedBy;
    }

    public Instant getActivatedAt() {
        return activatedAt;
    }

    public String getActivationTicket() {
        return activationTicket;
    }

    /**
     * Activates the nomination and clears any prior deactivation, so a
     * reactivated nomination does not carry a stale reason or actor.
     */
    public void activate(String adminId, String ticketReference) {
        this.status = NominationStatus.ACTIVE;
        this.activatedBy = adminId;
        this.activatedAt = Instant.now();
        this.activationTicket = ticketReference;
        this.deactivatedBy = null;
        this.deactivatedAt = null;
        this.deactivationReason = null;
    }

    public String getDeactivatedBy() {
        return deactivatedBy;
    }

    public Instant getDeactivatedAt() {
        return deactivatedAt;
    }

    public String getDeactivationReason() {
        return deactivationReason;
    }

    public void deactivate(String adminId, String reason) {
        this.status = NominationStatus.DEACTIVATED;
        this.deactivatedBy = adminId;
        this.deactivatedAt = Instant.now();
        this.deactivationReason = reason;
    }

    public boolean isActiveFor(String ownerId, String nomineeId) {
        return this.status == NominationStatus.ACTIVE
                && this.ownerId.equals(ownerId)
                && this.nomineeId.equals(nomineeId);
    }
}
