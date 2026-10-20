package com.ixayda.iam.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Mutable refresh bounds, authenticated inside the corresponding protected native authorization. */
public record IdentityRefreshFamily(UUID authorizationId, long version, long generation, String currentDigest, Set<String> scopes,
		Instant startedAt, Instant updatedAt, Instant idleExpiresAt, Instant absoluteExpiresAt, Status status) {

	public IdentityRefreshFamily {
		Objects.requireNonNull(authorizationId); Objects.requireNonNull(startedAt); Objects.requireNonNull(updatedAt);
		Objects.requireNonNull(idleExpiresAt); Objects.requireNonNull(absoluteExpiresAt); Objects.requireNonNull(status);
		scopes = Set.copyOf(scopes);
		if (version < 1 || generation < 0 || currentDigest == null || !currentDigest.matches("[0-9a-f]{64}") || scopes.isEmpty()
				|| !Set.of("openid", "profile", "offline_access").containsAll(scopes) || updatedAt.isBefore(startedAt)
				|| !idleExpiresAt.isAfter(startedAt) || !absoluteExpiresAt.isAfter(startedAt) || idleExpiresAt.isAfter(absoluteExpiresAt)
				|| idleExpiresAt.isAfter(updatedAt.plus(7, ChronoUnit.DAYS)) || absoluteExpiresAt.isAfter(startedAt.plus(30, ChronoUnit.DAYS))
				|| status == Status.ACTIVE && (!scopes.contains("offline_access") || !idleExpiresAt.isAfter(updatedAt))
				|| status == Status.CLOSED && scopes.contains("offline_access")) { throw new IllegalArgumentException("Refresh family is invalid"); }
	}

	public enum Status { ACTIVE, CLOSED, QUARANTINED, REVOKED }

	@Override public String toString() { return "IdentityRefreshFamily[REDACTED]"; }

}
