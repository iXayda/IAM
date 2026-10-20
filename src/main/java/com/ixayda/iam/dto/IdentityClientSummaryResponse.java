package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.IdentityClient;

/** Compact listing projection; full configuration is retrieved through the detail operation. */
public record IdentityClientSummaryResponse(UUID id, String displayName, UUID resourceId, IdentityClient.Status status,
		long version, Instant createdAt, Instant updatedAt, Instant secretRotatedAt) { }
