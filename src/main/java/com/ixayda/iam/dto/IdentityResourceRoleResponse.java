package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResourceRole;

public record IdentityResourceRoleResponse(UUID id, UUID resourceId, String code, String displayName, IdentityResourceRole.Status status,
		long version, Instant createdAt, Instant updatedAt) { }
