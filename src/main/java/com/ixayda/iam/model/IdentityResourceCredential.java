package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Public lifecycle facts for one resource's validation credential; never contains its secret or hash. */
public record IdentityResourceCredential(UUID resourceId, Status status, long version,
		Instant createdAt, Instant rotatedAt, Instant updatedAt) {

	public enum Status { ACTIVE, DISABLED }

}
