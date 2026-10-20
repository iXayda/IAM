package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** An application resource has a stable identity and an exact, case-sensitive token audience. */
public record IdentityResource(UUID id, String audience, String displayName, Status status,
		long version, Instant createdAt, Instant updatedAt) {

	public enum Status { ACTIVE, DISABLED }

}
