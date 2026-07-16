package com.ixayda.iam.client;

import java.time.Instant;
import java.util.Objects;

public record ClientSecretMetadata(Instant issuedAt, Instant expiresAt) {

	public ClientSecretMetadata {
		Objects.requireNonNull(issuedAt, "Client secret issue time must not be null");
		Objects.requireNonNull(expiresAt, "Client secret expiration time must not be null");
		if (!expiresAt.isAfter(issuedAt)) {
			throw new IllegalArgumentException("Client secret expiration time must be after its issue time");
		}
	}

	public boolean isExpiredAt(Instant instant) {
		Objects.requireNonNull(instant, "Client secret expiration check time must not be null");
		return !instant.isBefore(this.expiresAt);
	}

}
