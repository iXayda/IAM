package com.ixayda.iam.organization;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record OrganizationMembership(TenantId tenantId, OrganizationId organizationId, UserId userId,
		OrganizationMembershipStatus status, long version, Instant createdAt, Instant updatedAt) {

	public OrganizationMembership {
		Objects.requireNonNull(tenantId, "Membership tenant ID must not be null");
		Objects.requireNonNull(organizationId, "Membership organization ID must not be null");
		Objects.requireNonNull(userId, "Membership user ID must not be null");
		Objects.requireNonNull(status, "Membership status must not be null");
		Objects.requireNonNull(createdAt, "Membership creation time must not be null");
		Objects.requireNonNull(updatedAt, "Membership update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("Membership version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Membership update time must not be before its creation time");
		}
	}

	public static OrganizationMembership active(TenantId tenantId, OrganizationId organizationId, UserId userId,
			Instant createdAt) {
		return new OrganizationMembership(tenantId, organizationId, userId, OrganizationMembershipStatus.ACTIVE, 0,
				createdAt, createdAt);
	}

	public boolean isActive() {
		return this.status == OrganizationMembershipStatus.ACTIVE;
	}

	public OrganizationMembership activate(Instant changedAt) {
		return changeStatus(OrganizationMembershipStatus.ACTIVE, changedAt);
	}

	public OrganizationMembership remove(Instant changedAt) {
		return changeStatus(OrganizationMembershipStatus.REMOVED, changedAt);
	}

	private OrganizationMembership changeStatus(OrganizationMembershipStatus targetStatus, Instant changedAt) {
		Objects.requireNonNull(changedAt, "Membership status change time must not be null");
		if (this.status == targetStatus) {
			return this;
		}
		Instant effectiveChangedAt = changedAt.isBefore(this.updatedAt) ? this.updatedAt : changedAt;
		return new OrganizationMembership(this.tenantId, this.organizationId, this.userId, targetStatus,
				Math.incrementExact(this.version), this.createdAt, effectiveChangedAt);
	}

}
