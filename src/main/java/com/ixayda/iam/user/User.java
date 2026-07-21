package com.ixayda.iam.user;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public record User(UserId id, TenantId tenantId, List<LoginIdentifier> identifiers, UserProfile profile,
		UserStatus status, long version, long securityVersion, Instant createdAt, Instant updatedAt,
		Instant lastLoginAt) {

	public User(UserId id, TenantId tenantId, List<LoginIdentifier> identifiers, UserStatus status, long version,
			Instant createdAt, Instant updatedAt, Instant lastLoginAt) {
		this(id, tenantId, identifiers, UserProfile.empty(), status, version, version, createdAt, updatedAt, lastLoginAt);
	}

	public User(UserId id, TenantId tenantId, List<LoginIdentifier> identifiers, UserProfile profile,
			UserStatus status, long version, Instant createdAt, Instant updatedAt, Instant lastLoginAt) {
		this(id, tenantId, identifiers, profile, status, version, version, createdAt, updatedAt, lastLoginAt);
	}

	public User {
		Objects.requireNonNull(id, "User ID must not be null");
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		identifiers = LoginIdentifier.validatedCopy(identifiers);
		Objects.requireNonNull(profile, "User profile must not be null");
		Objects.requireNonNull(status, "User status must not be null");
		Objects.requireNonNull(createdAt, "User creation time must not be null");
		Objects.requireNonNull(updatedAt, "User update time must not be null");
		if (version < 0 || securityVersion < 0 || securityVersion > version) {
			throw new IllegalArgumentException(
					"User version and security version must be non-negative, with security version not ahead of version");
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

	public User updateProfile(UserProfile replacement, Instant changedAt) {
		Objects.requireNonNull(replacement, "User profile must not be null");
		Objects.requireNonNull(changedAt, "User profile change time must not be null");
		if (this.profile.equals(replacement)) {
			return this;
		}
		if (isDeleted()) {
			throw new IllegalStateException("Deleted user profile cannot be changed");
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("User profile change time must not be before its last update");
		}
		return new User(this.id, this.tenantId, this.identifiers, replacement, this.status,
				Math.incrementExact(this.version), this.securityVersion, this.createdAt, changedAt, this.lastLoginAt);
	}

	public User replace(ReplaceUserRequest replacement, Instant changedAt) {
		Objects.requireNonNull(replacement, "User replacement must not be null");
		Objects.requireNonNull(changedAt, "User replacement time must not be null");
		if (isDeleted()) {
			throw new IllegalStateException("Deleted user cannot be replaced");
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("User replacement time must not be before its last update");
		}
		UserStatus replacementStatus = replacementStatus(replacement.active());
		boolean identifiersChanged = !this.identifiers.equals(replacement.identifiers());
		boolean profileChanged = !this.profile.equals(replacement.profile());
		boolean statusChanged = this.status != replacementStatus;
		if (!identifiersChanged && !profileChanged && !statusChanged) {
			return this;
		}
		long replacementSecurityVersion = identifiersChanged || statusChanged
				? Math.incrementExact(this.securityVersion)
				: this.securityVersion;
		return new User(this.id, this.tenantId, replacement.identifiers(), replacement.profile(), replacementStatus,
				Math.incrementExact(this.version), replacementSecurityVersion, this.createdAt, changedAt, this.lastLoginAt);
	}

	public User membershipsChanged(Instant changedAt) {
		Objects.requireNonNull(changedAt, "User membership change time must not be null");
		if (isDeleted()) {
			throw new IllegalStateException("Deleted user memberships cannot be changed");
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("User membership change time must not be before its last update");
		}
		return new User(this.id, this.tenantId, this.identifiers, this.profile, this.status,
				Math.incrementExact(this.version), this.securityVersion, this.createdAt, changedAt, this.lastLoginAt);
	}

	public User credentialsChanged(Instant changedAt) {
		Objects.requireNonNull(changedAt, "User credential change time must not be null");
		if (isDeleted()) {
			throw new IllegalStateException("Deleted user credentials cannot be changed");
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("User credential change time must not be before its last update");
		}
		return new User(this.id, this.tenantId, this.identifiers, this.profile, this.status,
				Math.incrementExact(this.version), Math.incrementExact(this.securityVersion), this.createdAt, changedAt,
				this.lastLoginAt);
	}

	@Override
	public String toString() {
		return "User[id=" + this.id + ", tenantId=" + this.tenantId + ", status=" + this.status + ", version="
				+ this.version + ", securityVersion=" + this.securityVersion + ", createdAt=" + this.createdAt
				+ ", updatedAt=" + this.updatedAt + ", lastLoginAt="
				+ this.lastLoginAt + ", identifierCount=" + this.identifiers.size() + ", profilePresent="
				+ !this.profile.isEmpty() + "]";
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
		return new User(this.id, this.tenantId, this.identifiers, this.profile, targetStatus,
				Math.incrementExact(this.version), Math.incrementExact(this.securityVersion),
				this.createdAt, changedAt, this.lastLoginAt);
	}

	private UserStatus replacementStatus(Boolean active) {
		if (active == null || (!active && !isActive())) {
			return this.status;
		}
		return active ? UserStatus.ACTIVE : UserStatus.DISABLED;
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
