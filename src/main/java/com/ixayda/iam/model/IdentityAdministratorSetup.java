package com.ixayda.iam.model;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Committed bootstrap preparation; an empty enrollment means the existing active factor is retained. */
public record IdentityAdministratorSetup(UUID userId, Optional<IdentityTotpEnrollment> enrollment) {

	public IdentityAdministratorSetup {
		Objects.requireNonNull(userId);
		Objects.requireNonNull(enrollment);
		if (enrollment.isPresent() && !enrollment.orElseThrow().userId().equals(userId)) {
			throw new IllegalArgumentException("Enrollment belongs to another user");
		}
	}

}
