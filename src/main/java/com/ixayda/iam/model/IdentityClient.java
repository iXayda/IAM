package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** A stable confidential application identity; no secret or secret hash is exposed. */
public record IdentityClient(UUID id, IdentityClientConfiguration configuration, Status status, long version,
		Instant createdAt, Instant updatedAt, Instant secretRotatedAt) {

	public enum Status { ACTIVE, DISABLED }

}
