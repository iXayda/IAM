package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

public record IdentityUserRoleResponse(UUID userId, UUID resourceId, UUID roleId, Instant createdAt) { }
