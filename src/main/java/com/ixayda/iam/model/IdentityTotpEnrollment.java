package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Sensitive registration material returned once, only after issuance commits. */
public record IdentityTotpEnrollment(UUID userId, UUID factorId, String secret, String provisioningUri, Instant expiresAt) {

	@Override
	public String toString() {
		return "IdentityTotpEnrollment[userId=" + this.userId + ", factorId=" + this.factorId + ", expiresAt=" + this.expiresAt + ", secret=REDACTED]";
	}

}
