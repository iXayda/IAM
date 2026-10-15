package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** User details without password credentials. */
public record IdentityUser(UUID id, String username, String displayName, Status status, Instant createdAt) {

	public enum Status {
		PENDING, ACTIVE, DISABLED
	}

}
