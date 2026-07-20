package com.ixayda.iam.session;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record UserSession(SessionId id, TenantId tenantId, UserId userId,
		SessionAuthenticationMethod authenticationMethod, Set<SessionAuthenticationFactor> authenticationFactors,
		SessionStatus status, long issuedTenantVersion, long issuedUserVersion, long version, Instant authenticatedAt,
		Instant updatedAt, Instant expiresAt, Instant revokedAt) {

	public UserSession {
		Objects.requireNonNull(id, "Session ID must not be null");
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(authenticationMethod, "Session authentication method must not be null");
		Objects.requireNonNull(authenticationFactors, "Session authentication factors must not be null");
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
		authenticationFactors = validatedFactors(authenticationMethod, authenticationFactors, authenticatedAt);
		validateRevocation(status, authenticatedAt, updatedAt, revokedAt);
	}

	public static UserSession start(SessionId id, TenantId tenantId, UserId userId,
			SessionAuthenticationMethod authenticationMethod, long issuedTenantVersion, long issuedUserVersion,
			Instant authenticatedAt, Instant expiresAt) {
		return start(id, tenantId, userId, authenticationMethod,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, authenticatedAt)),
				issuedTenantVersion, issuedUserVersion, authenticatedAt, expiresAt);
	}

	public static UserSession start(SessionId id, TenantId tenantId, UserId userId,
			SessionAuthenticationMethod authenticationMethod, Set<SessionAuthenticationFactor> authenticationFactors,
			long issuedTenantVersion, long issuedUserVersion, Instant authenticatedAt, Instant expiresAt) {
		return new UserSession(id, tenantId, userId, authenticationMethod, authenticationFactors,
				SessionStatus.ACTIVE, issuedTenantVersion, issuedUserVersion, 0, authenticatedAt, authenticatedAt,
				expiresAt, null);
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
				this.authenticationFactors, SessionStatus.REVOKED, this.issuedTenantVersion, this.issuedUserVersion,
				Math.incrementExact(this.version), this.authenticatedAt, effectiveRevocationTime, this.expiresAt,
				effectiveRevocationTime);
	}

	private static Set<SessionAuthenticationFactor> validatedFactors(SessionAuthenticationMethod method,
			Set<SessionAuthenticationFactor> factors, Instant authenticatedAt) {
		EnumMap<SessionAuthenticationFactorType, SessionAuthenticationFactor> byType =
				new EnumMap<>(SessionAuthenticationFactorType.class);
		for (SessionAuthenticationFactor factor : factors) {
			Objects.requireNonNull(factor, "Session authentication factor must not be null");
			if (factor.issuedAt().isAfter(authenticatedAt)) {
				throw new IllegalArgumentException(
						"Session authentication factor issuance time must not be after authentication time");
			}
			SessionAuthenticationFactor normalized = new SessionAuthenticationFactor(factor.type(),
					factor.issuedAt().truncatedTo(ChronoUnit.MICROS));
			if (byType.put(normalized.type(), normalized) != null) {
				throw new IllegalArgumentException("Session authentication factor types must be unique");
			}
		}
		if (method == SessionAuthenticationMethod.PASSWORD
				&& !byType.containsKey(SessionAuthenticationFactorType.PASSWORD)) {
			throw new IllegalArgumentException("Password sessions must contain password authentication evidence");
		}
		return Collections.unmodifiableSet(new LinkedHashSet<>(byType.values()));
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
