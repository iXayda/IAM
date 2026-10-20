package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Public management identity is independent of the bearer cookie and survives MFA cookie rotation. */
public record IdentityBrowserSessionSummary(UUID id, Instant createdAt, Instant authenticatedAt, Instant lastAccessedAt,
		Instant idleExpiresAt, Instant absoluteExpiresAt, boolean current) { }
