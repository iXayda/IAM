package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** A resource-scoped role keeps its identity and code across disable and enable operations. */
public record IdentityResourceRole(UUID id, UUID resourceId, String code, String displayName, Status status,
		long version, Instant createdAt, Instant updatedAt) {

	public enum Status { ACTIVE, DISABLED }

}
