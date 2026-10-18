package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** Once-delivered, committed material for factor rebuilding only; never a login or management grant. */
public record IdentityTotpRecovery(UUID userId, UUID recoveryId, String token, IdentityTotpEnrollment enrollment) {

	public IdentityTotpRecovery {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(recoveryId, "Recovery id is required");
		Objects.requireNonNull(token, "Recovery token is required");
		Objects.requireNonNull(enrollment, "New factor enrollment is required");
		if (!userId.equals(enrollment.userId())) { throw new IllegalArgumentException("Recovery owner does not match enrollment"); }
	}

	@Override
	public String toString() {
		return "IdentityTotpRecovery[userId=" + this.userId + ", recoveryId=" + this.recoveryId
				+ ", token=REDACTED, enrollment=REDACTED]";
	}

}
