package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResource;

public record IdentityResourceResponse(UUID id, String audience, String displayName, IdentityResource.Status status,
		long version, Instant createdAt, Instant updatedAt) { }
