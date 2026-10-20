package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A purpose-bound keyed digest, never the bearer token; spent entries outlive their individual expiry. */
public record IdentityRefreshHistory(UUID authorizationId, String digest, long generation, String parentDigest,
		Instant issuedAt, Instant expiresAt, Instant consumedAt) {

	public IdentityRefreshHistory {
		Objects.requireNonNull(authorizationId); Objects.requireNonNull(issuedAt); Objects.requireNonNull(expiresAt);
		if (digest == null || !digest.matches("[0-9a-f]{64}") || generation < 0 || (generation == 0) != (parentDigest == null)
				|| parentDigest != null && (!parentDigest.matches("[0-9a-f]{64}") || parentDigest.equals(digest))
				|| !expiresAt.isAfter(issuedAt) || consumedAt != null && (consumedAt.isBefore(issuedAt) || !consumedAt.isBefore(expiresAt))) {
			throw new IllegalArgumentException("Refresh history is invalid");
		}
	}

	@Override public String toString() { return "IdentityRefreshHistory[REDACTED]"; }

}
