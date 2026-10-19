package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** Committed deployment material for rebuilding an existing administrator's factor only. */
public record IdentityAdministratorRecovery(UUID userId, UUID recoveryId, String token, IdentityTotpEnrollment enrollment) {

	public IdentityAdministratorRecovery {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(recoveryId, "Recovery id is required");
		Objects.requireNonNull(token, "Recovery token is required");
		Objects.requireNonNull(enrollment, "New factor enrollment is required");
		if (!userId.equals(enrollment.userId())) { throw new IllegalArgumentException("Recovery owner does not match enrollment"); }
	}

	@Override
	public String toString() {
		return "IdentityAdministratorRecovery[userId=" + this.userId + ", recoveryId=" + this.recoveryId
				+ ", token=REDACTED, enrollment=REDACTED]";
	}

}
