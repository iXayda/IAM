package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** Once-delivered, committed material for factor replacement only; never a login or management grant. */
public record IdentityTotpReplacement(UUID userId, UUID replacementId, String token, IdentityTotpEnrollment enrollment) {

	public IdentityTotpReplacement {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(replacementId, "Replacement id is required");
		Objects.requireNonNull(token, "Replacement token is required");
		Objects.requireNonNull(enrollment, "New factor enrollment is required");
		if (!userId.equals(enrollment.userId())) { throw new IllegalArgumentException("Replacement owner does not match enrollment"); }
	}

	@Override
	public String toString() {
		return "IdentityTotpReplacement[userId=" + this.userId + ", replacementId=" + this.replacementId
				+ ", token=REDACTED, enrollment=REDACTED]";
	}

}
