package com.ixayda.iam.session;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record UserSession(SessionId id, TenantId tenantId, UserId userId,
		SessionAuthenticationMethod authenticationMethod, SessionStatus status, long issuedTenantVersion,
		long issuedUserVersion, long version, Instant authenticatedAt, Instant updatedAt, Instant expiresAt,
		Instant revokedAt) {

	public UserSession {
		Objects.requireNonNull(id, "Session ID must not be null");
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(authenticationMethod, "Session authentication method must not be null");
		Objects.requireNonNull(status, "Session status must not be null");
		Objects.requireNonNull(authenticatedAt, "Session authentication time must not be null");
		Objects.requireNonNull(updatedAt, "Session update time must not be null");
		Objects.requireNonNull(expiresAt, "Session expiration time must not be null");
		if (issuedTenantVersion < 0 || issuedUserVersion < 0 || version < 0) {
			throw new IllegalArgumentException("Session versions must not be negative");
		}
		if (updatedAt.isBefore(authenticatedAt)) {
			throw new IllegalArgumentException("Session update time must not be before authentication time");
		}
		if (!expiresAt.isAfter(authenticatedAt)) {
			throw new IllegalArgumentException("Session expiration time must be after authentication time");
		}
		validateRevocation(status, authenticatedAt, updatedAt, revokedAt);
	}

	public static UserSession start(SessionId id, TenantId tenantId, UserId userId,
			SessionAuthenticationMethod authenticationMethod, long issuedTenantVersion, long issuedUserVersion,
			Instant authenticatedAt, Instant expiresAt) {
		return new UserSession(id, tenantId, userId, authenticationMethod, SessionStatus.ACTIVE,
				issuedTenantVersion, issuedUserVersion, 0, authenticatedAt, authenticatedAt, expiresAt, null);
	}

	public boolean isRevoked() {
		return this.status == SessionStatus.REVOKED;
	}

	public boolean isExpiredAt(Instant instant) {
		Objects.requireNonNull(instant, "Session expiration check time must not be null");
		return !instant.isBefore(this.expiresAt);
	}

	public UserSession revoke(Instant revokedAt) {
		Objects.requireNonNull(revokedAt, "Session revocation time must not be null");
		if (this.status == SessionStatus.REVOKED) {
			return this;
		}
		Instant effectiveRevocationTime = revokedAt.isBefore(this.updatedAt) ? this.updatedAt : revokedAt;
		return new UserSession(this.id, this.tenantId, this.userId, this.authenticationMethod,
				SessionStatus.REVOKED, this.issuedTenantVersion, this.issuedUserVersion,
				Math.incrementExact(this.version), this.authenticatedAt, effectiveRevocationTime, this.expiresAt,
				effectiveRevocationTime);
	}

	private static void validateRevocation(SessionStatus status, Instant authenticatedAt, Instant updatedAt,
			Instant revokedAt) {
		if (status == SessionStatus.ACTIVE && revokedAt != null) {
			throw new IllegalArgumentException("Active session must not have a revocation time");
		}
		if (status == SessionStatus.REVOKED) {
			if (revokedAt == null) {
				throw new IllegalArgumentException("Revoked session must have a revocation time");
			}
			if (revokedAt.isBefore(authenticatedAt)) {
				throw new IllegalArgumentException("Session revocation time must not be before authentication time");
			}
			if (updatedAt.isBefore(revokedAt)) {
				throw new IllegalArgumentException("Session update time must not be before revocation time");
			}
		}
	}

}
