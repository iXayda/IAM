package com.ixayda.iam.user;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public record User(UserId id, TenantId tenantId, List<LoginIdentifier> identifiers, UserStatus status, long version,
		Instant createdAt, Instant updatedAt, Instant lastLoginAt) {

	public User {
		Objects.requireNonNull(id, "User ID must not be null");
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		identifiers = LoginIdentifier.validatedCopy(identifiers);
		Objects.requireNonNull(status, "User status must not be null");
		Objects.requireNonNull(createdAt, "User creation time must not be null");
		Objects.requireNonNull(updatedAt, "User update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("User version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("User update time must not be before its creation time");
		}
		if (lastLoginAt != null && lastLoginAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("User last login time must not be before its creation time");
		}
	}

	public boolean isActive() {
		return this.status == UserStatus.ACTIVE;
	}

	public boolean isDeleted() {
		return this.status == UserStatus.DELETED;
	}

	public User activate(Instant changedAt) {
		return changeStatus(UserStatus.ACTIVE, changedAt);
	}

	public User disable(Instant changedAt) {
		return changeStatus(UserStatus.DISABLED, changedAt);
	}

	public User lock(Instant changedAt) {
		return changeStatus(UserStatus.LOCKED, changedAt);
	}

	public User delete(Instant changedAt) {
		return changeStatus(UserStatus.DELETED, changedAt);
	}

	@Override
	public String toString() {
		return "User[id=" + this.id + ", tenantId=" + this.tenantId + ", status=" + this.status + ", version="
				+ this.version + ", createdAt=" + this.createdAt + ", updatedAt=" + this.updatedAt + ", lastLoginAt="
				+ this.lastLoginAt + ", identifierCount=" + this.identifiers.size() + "]";
	}

	private User changeStatus(UserStatus targetStatus, Instant changedAt) {
		Objects.requireNonNull(changedAt, "User status change time must not be null");
		if (this.status == targetStatus) {
			return this;
		}
		if (!canTransitionTo(targetStatus)) {
			throw new InvalidUserStatusTransitionException(this.id, this.status, targetStatus);
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("User status change time must not be before its last update");
		}
		return new User(this.id, this.tenantId, this.identifiers, targetStatus, Math.incrementExact(this.version),
				this.createdAt, changedAt, this.lastLoginAt);
	}

	private boolean canTransitionTo(UserStatus targetStatus) {
		return switch (targetStatus) {
			case ACTIVE -> this.status == UserStatus.DISABLED || this.status == UserStatus.LOCKED;
			case DISABLED -> this.status == UserStatus.ACTIVE || this.status == UserStatus.LOCKED;
			case LOCKED -> this.status == UserStatus.ACTIVE;
			case DELETED -> this.status != UserStatus.DELETED;
		};
	}

}
