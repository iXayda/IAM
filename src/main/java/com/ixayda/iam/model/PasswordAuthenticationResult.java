package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** The credential version verified in the password transaction; contains no password or transport details. */
public record PasswordAuthenticationResult(UUID userId, long credentialVersion, UUID correlationId) {

	public PasswordAuthenticationResult {
		Objects.requireNonNull(userId, "Authenticated user id is required");
		Objects.requireNonNull(correlationId, "Authentication correlation id is required");
		if (credentialVersion < 1) {
			throw new IllegalArgumentException("Credential version must be positive");
		}
	}

}
