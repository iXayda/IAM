package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.Objects;

record AuthorizationAuthoritySnapshot(String authority, Instant issuedAt) {

	AuthorizationAuthoritySnapshot {
		Objects.requireNonNull(authority, "Authorization authority must not be null");
		boolean factor = authority.startsWith("FACTOR_");
		if (factor && issuedAt == null) {
			throw new IllegalArgumentException("Authorization factor authority must have an issuance time");
		}
		if (!factor && issuedAt != null) {
			throw new IllegalArgumentException("Non-factor authorization authority must not have an issuance time");
		}
		if (issuedAt != null && issuedAt.isBefore(Instant.EPOCH)) {
			throw new IllegalArgumentException("Authorization factor issuance time must not be before the epoch");
		}
	}

}
