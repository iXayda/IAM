package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Committed recovery secrets for one-time trusted delivery, never a normal profile response. */
public record MfaRecoveryCodeSet(UUID userId, UUID factorId, UUID generationId, List<String> codes, Instant issuedAt) {

	public MfaRecoveryCodeSet {
		Objects.requireNonNull(userId, "User id is required");
		Objects.requireNonNull(factorId, "Factor id is required");
		Objects.requireNonNull(generationId, "Generation id is required");
		codes = List.copyOf(codes);
		Objects.requireNonNull(issuedAt, "Issue time is required");
	}

	@Override
	public String toString() {
		return "MfaRecoveryCodeSet[userId=" + this.userId + ", factorId=" + this.factorId
				+ ", generationId=" + this.generationId + ", codes=REDACTED, issuedAt=" + this.issuedAt + "]";
	}

}
