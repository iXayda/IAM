package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** Owner-visible grant metadata; neither this identifier nor its state is an access credential. */
public record IdentityAuthorizationSummary(UUID id, UUID clientId, String clientName, UUID resourceId, String resourceName,
		String audience, Instant issuedAt, Instant expiresAt, Set<String> scopes, Status status) {

	public IdentityAuthorizationSummary { scopes = Set.copyOf(scopes); }
	public enum Status { PENDING, ACTIVE, EXPIRED, INACTIVE, REVOKED, QUARANTINED }
}
