package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** Authentication evidence supplied by a trusted browser adapter, never by request fields. */
public record IdentityBrowserContext(UUID userId, String sessionId, long authenticatedAt, long credentialVersion, UUID correlationId) {

	public IdentityBrowserContext {
		Objects.requireNonNull(userId, "Authenticated identity is required"); Objects.requireNonNull(correlationId, "Correlation id is required");
		if (sessionId == null || sessionId.isBlank() || credentialVersion < 1 || authenticatedAt < 1) { throw new IllegalArgumentException("Browser authentication evidence is invalid"); }
	}

	@Override public String toString() { return "IdentityBrowserContext[REDACTED]"; }
}
