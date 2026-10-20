package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Immutable original bounds of one authorization code; later token issuance cannot substitute a different resource. */
public record IdentityAuthorizationBinding(UUID id, IdentityAuthorizationSession session, Set<String> scopes,
		Instant issuedAt, Instant codeExpiresAt) {

	public IdentityAuthorizationBinding {
		Objects.requireNonNull(id); Objects.requireNonNull(session); Objects.requireNonNull(issuedAt); Objects.requireNonNull(codeExpiresAt);
		scopes = Set.copyOf(scopes);
		if (!scopes.contains("openid") || !Set.of("openid", "profile", "offline_access").containsAll(scopes)
				|| issuedAt.isBefore(session.authenticatedAt()) || !codeExpiresAt.isAfter(issuedAt)
				|| codeExpiresAt.isAfter(issuedAt.plusSeconds(60)) || codeExpiresAt.isAfter(session.expiresAt())) {
			throw new IllegalArgumentException("Authorization binding is invalid");
		}
	}

	@Override
	public String toString() { return "IdentityAuthorizationBinding[REDACTED]"; }

}
