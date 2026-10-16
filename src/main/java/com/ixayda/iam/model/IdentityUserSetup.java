package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A newly issued secret for trusted delivery; never use as a profile or log value. */
public record IdentityUserSetup(UUID userId, String token, Instant expiresAt) {

	public IdentityUserSetup {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(token, "Setup token is required");
		Objects.requireNonNull(expiresAt, "Expiry is required");
	}

	@Override
	public String toString() {
		return "IdentityUserSetup[userId=" + this.userId + ", token=[REDACTED], expiresAt=" + this.expiresAt + "]";
	}

}
