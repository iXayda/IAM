package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Locked application identity and persisted browser facts; the session identifier is the internal primary key. */
public record IdentityAuthorizationSession(IdentityApplicationAccess access, UUID browserSessionId,
		Instant authenticatedAt, Instant idleExpiresAt, Instant absoluteExpiresAt) {

	public IdentityAuthorizationSession {
		Objects.requireNonNull(access); Objects.requireNonNull(browserSessionId);
		Objects.requireNonNull(authenticatedAt); Objects.requireNonNull(idleExpiresAt); Objects.requireNonNull(absoluteExpiresAt);
		if (!authenticatedAt.isBefore(idleExpiresAt) || !authenticatedAt.isBefore(absoluteExpiresAt)) {
			throw new IllegalArgumentException("Application authentication deadlines are invalid");
		}
	}

	public Instant expiresAt() { return this.idleExpiresAt.isBefore(this.absoluteExpiresAt) ? this.idleExpiresAt : this.absoluteExpiresAt; }

	@Override
	public String toString() { return "IdentityAuthorizationSession[REDACTED]"; }

}
