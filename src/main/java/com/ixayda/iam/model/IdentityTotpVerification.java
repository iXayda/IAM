package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** A committed factor decision, not a browser session or a grant of management permission. */
public record IdentityTotpVerification(UUID userId, UUID factorId, long credentialVersion, long step,
		Instant verifiedAt, UUID correlationId) {

}
