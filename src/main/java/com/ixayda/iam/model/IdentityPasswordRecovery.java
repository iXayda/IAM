package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A one-time recovery secret for trusted delivery after its transaction commits. */
public record IdentityPasswordRecovery(UUID userId, String token, Instant expiresAt) {

	public IdentityPasswordRecovery {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(token, "Recovery token is required");
		Objects.requireNonNull(expiresAt, "Expiry is required");
	}

	@Override
	public String toString() {
		return "IdentityPasswordRecovery[userId=" + this.userId + ", token=[REDACTED], expiresAt=" + this.expiresAt + "]";
	}

}
