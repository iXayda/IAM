package com.ixayda.iam.model;

import java.io.Serializable;
import java.io.Serial;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Server-issued evidence of a TOTP decision; membership and current credentials still require checking. */
public record IdentityAdministratorAuthentication(UUID userId, UUID factorId, long credentialVersion,
		long passwordAuthenticatedAt, Instant verifiedAt) implements Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	public IdentityAdministratorAuthentication {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(factorId, "Factor id is required");
		Objects.requireNonNull(verifiedAt, "Verification time is required");
		if (credentialVersion < 1 || passwordAuthenticatedAt < 1) {
			throw new IllegalArgumentException("Current password evidence is required");
		}
	}

}
