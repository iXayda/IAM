package com.ixayda.iam.admin;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record AdminRoleBinding(AdminRoleBindingId id, TenantId tenantId, UserId userId, AdminRoleCode roleCode,
		AdminRoleBindingType type, AdminRoleBindingStatus status, UserId createdByUserId, String reason,
		Instant expiresAt, long version, Instant createdAt, Instant updatedAt, UserId revokedByUserId,
		Instant revokedAt) {

	public static final Duration MAXIMUM_JIT_DURATION = Duration.ofHours(8);

	public AdminRoleBinding {
		Objects.requireNonNull(id, "Admin role binding ID must not be null");
		Objects.requireNonNull(tenantId, "Admin role binding tenant ID must not be null");
		Objects.requireNonNull(userId, "Admin role binding user ID must not be null");
		Objects.requireNonNull(roleCode, "Admin role binding role code must not be null");
		Objects.requireNonNull(type, "Admin role binding type must not be null");
		Objects.requireNonNull(status, "Admin role binding status must not be null");
		Objects.requireNonNull(createdAt, "Admin role binding creation time must not be null");
		Objects.requireNonNull(updatedAt, "Admin role binding update time must not be null");
		reason = normalizeReason(reason);
		if (version < 0) {
			throw new IllegalArgumentException("Admin role binding version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Admin role binding update time must not precede its creation time");
		}
		if (createdByUserId != null && createdByUserId.equals(userId)) {
			throw new IllegalArgumentException("Admin role bindings cannot be self-granted");
		}
		validateLifetime(type, createdByUserId, reason, expiresAt, createdAt);
		validateRevocation(status, userId, revokedByUserId, revokedAt, createdAt, updatedAt);
	}

	public static AdminRoleBinding bootstrap(TenantId tenantId, UserId userId, Instant createdAt) {
		return active(tenantId, userId, AdminRoleCode.SUPER_ADMIN, AdminRoleBindingType.PERMANENT, null,
				"Initial administrator bootstrap", null, createdAt);
	}

	public static AdminRoleBinding permanent(TenantId tenantId, UserId userId, AdminRoleCode roleCode,
			UserId createdByUserId, String reason, Instant createdAt) {
		Objects.requireNonNull(createdByUserId, "Permanent admin role grantor must not be null");
		return active(tenantId, userId, roleCode, AdminRoleBindingType.PERMANENT, createdByUserId, reason, null,
				createdAt);
	}

	public static AdminRoleBinding justInTime(TenantId tenantId, UserId userId, AdminRoleCode roleCode,
			UserId createdByUserId, String reason, Instant expiresAt, Instant createdAt) {
		return active(tenantId, userId, roleCode, AdminRoleBindingType.JIT, createdByUserId, reason, expiresAt,
				createdAt);
	}

	public boolean isEffectiveAt(Instant instant) {
		Objects.requireNonNull(instant, "Admin role binding evaluation time must not be null");
		return this.status == AdminRoleBindingStatus.ACTIVE
				&& (this.type == AdminRoleBindingType.PERMANENT || instant.isBefore(this.expiresAt));
	}

	public AdminRoleBinding revoke(UserId revokedBy, Instant changedAt) {
		Objects.requireNonNull(revokedBy, "Admin role revoker must not be null");
		Objects.requireNonNull(changedAt, "Admin role revocation time must not be null");
		if (revokedBy.equals(this.userId)) {
			throw new IllegalArgumentException("Admin role bindings cannot be self-revoked");
		}
		if (this.status == AdminRoleBindingStatus.REVOKED) {
			return this;
		}
		Instant effectiveChangedAt = changedAt.isBefore(this.updatedAt) ? this.updatedAt : changedAt;
		return new AdminRoleBinding(this.id, this.tenantId, this.userId, this.roleCode, this.type,
				AdminRoleBindingStatus.REVOKED, this.createdByUserId, this.reason, this.expiresAt,
				Math.incrementExact(this.version), this.createdAt, effectiveChangedAt, revokedBy, effectiveChangedAt);
	}

	private static AdminRoleBinding active(TenantId tenantId, UserId userId, AdminRoleCode roleCode,
			AdminRoleBindingType type, UserId createdByUserId, String reason, Instant expiresAt, Instant createdAt) {
		return new AdminRoleBinding(AdminRoleBindingId.random(), tenantId, userId, roleCode, type,
				AdminRoleBindingStatus.ACTIVE, createdByUserId, reason, expiresAt, 0, createdAt, createdAt, null,
				null);
	}

	private static void validateLifetime(AdminRoleBindingType type, UserId createdByUserId, String reason,
			Instant expiresAt, Instant createdAt) {
		if (type == AdminRoleBindingType.PERMANENT) {
			if (expiresAt != null) {
				throw new IllegalArgumentException("Permanent admin role bindings must not expire");
			}
			return;
		}
		Objects.requireNonNull(createdByUserId, "JIT admin role grantor must not be null");
		if (reason == null) {
			throw new IllegalArgumentException("JIT admin role reason must not be null");
		}
		Objects.requireNonNull(expiresAt, "JIT admin role expiry must not be null");
		Duration duration = Duration.between(createdAt, expiresAt);
		if (duration.isZero() || duration.isNegative() || duration.compareTo(MAXIMUM_JIT_DURATION) > 0) {
			throw new IllegalArgumentException("JIT admin role expiry must be within eight hours of creation");
		}
	}

	private static void validateRevocation(AdminRoleBindingStatus status, UserId userId, UserId revokedByUserId,
			Instant revokedAt, Instant createdAt, Instant updatedAt) {
		if (status == AdminRoleBindingStatus.ACTIVE) {
			if (revokedByUserId != null || revokedAt != null) {
				throw new IllegalArgumentException("Active admin role bindings must not contain revocation metadata");
			}
			return;
		}
		Objects.requireNonNull(revokedByUserId, "Revoked admin role binding revoker must not be null");
		Objects.requireNonNull(revokedAt, "Revoked admin role binding time must not be null");
		if (revokedByUserId.equals(userId)) {
			throw new IllegalArgumentException("Admin role bindings cannot be self-revoked");
		}
		if (revokedAt.isBefore(createdAt) || !revokedAt.equals(updatedAt)) {
			throw new IllegalArgumentException("Admin role revocation time must be monotonic and equal update time");
		}
	}

	private static String normalizeReason(String reason) {
		if (reason == null) {
			return null;
		}
		String normalized = reason.strip();
		if (normalized.isEmpty() || normalized.length() > 500
				|| normalized.chars().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException("Admin role binding reason is invalid");
		}
		return normalized;
	}

}
