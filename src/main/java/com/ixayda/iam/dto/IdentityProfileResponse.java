package com.ixayda.iam.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityProfileResponse(
		@Schema(description = "用户唯一标识", requiredMode = Schema.RequiredMode.REQUIRED) UUID id,
		@Schema(description = "登录账号", minLength = 3, maxLength = 64, pattern = "^[a-z0-9._-]+$",
				requiredMode = Schema.RequiredMode.REQUIRED) String username,
		@Schema(description = "显示名称", minLength = 1, maxLength = 128,
				requiredMode = Schema.RequiredMode.REQUIRED) String displayName) {
}
