package com.ixayda.iam.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserRoleChangeResponse(UUID userId, UUID resourceId, UUID roleId, boolean changed,
		@Schema(description = "该用户在该资源的当前绑定版本", minimum = "0") long version) { }
