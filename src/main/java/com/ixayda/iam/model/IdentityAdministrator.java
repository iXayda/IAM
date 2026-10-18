package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Persistent IAM management eligibility; possession of this record is not an authenticated session. */
public record IdentityAdministrator(UUID userId, Instant grantedAt) {

	public IdentityAdministrator {
		Objects.requireNonNull(userId, "Administrator user id is required");
		Objects.requireNonNull(grantedAt, "Administrator grant time is required");
	}

}
