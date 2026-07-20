package com.ixayda.iam.session;

import java.time.Instant;
import java.util.Objects;

public record SessionAuthenticationFactor(SessionAuthenticationFactorType type, Instant issuedAt) {

	public SessionAuthenticationFactor {
		Objects.requireNonNull(type, "Session authentication factor type must not be null");
		Objects.requireNonNull(issuedAt, "Session authentication factor issuance time must not be null");
		if (issuedAt.isBefore(Instant.EPOCH)) {
			throw new IllegalArgumentException("Session authentication factor issuance time must not be before the epoch");
		}
	}

}
