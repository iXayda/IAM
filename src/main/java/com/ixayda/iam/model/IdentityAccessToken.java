package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Current online authorization projection; contains no bearer token or browser authentication. */
public record IdentityAccessToken(UUID authorizationId, IdentityApplicationAccess access, Set<String> scopes, Instant issuedAt, Instant expiresAt) {

	public IdentityAccessToken {
		Objects.requireNonNull(authorizationId); Objects.requireNonNull(access); Objects.requireNonNull(issuedAt); Objects.requireNonNull(expiresAt);
		scopes = Set.copyOf(scopes);
		if (scopes.isEmpty() || !Set.of("openid", "profile", "offline_access").containsAll(scopes)
				|| !expiresAt.isAfter(issuedAt) || expiresAt.isAfter(issuedAt.plusSeconds(300))) { throw new IllegalArgumentException("Access token bounds are invalid"); }
	}

	@Override public String toString() { return "IdentityAccessToken[REDACTED]"; }

}
