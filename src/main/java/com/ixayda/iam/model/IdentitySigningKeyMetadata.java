package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Public lifecycle metadata, without ciphertext or private material. */
public record IdentitySigningKeyMetadata(UUID id, String algorithm, Status status, Instant createdAt, Instant retiredAt, Instant verificationUntil, Instant compromisedAt) {
	public enum Status { ACTIVE, RETIRED, COMPROMISED }
}
