package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** A committed code consumption for factor rebuilding only; not MFA, a session or a management grant. */
public record MfaRecoveryCodeConsumption(UUID userId, UUID factorId, UUID generationId, long credentialVersion,
		Instant consumedAt, UUID correlationId) {

}
