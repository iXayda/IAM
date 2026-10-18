package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityPasswordChangeRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "当前密码", format = "password", writeOnly = true) String currentPassword,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "新密码，沿用密码策略", format = "password", writeOnly = true) String newPassword) {

	@Override
	public String toString() {
		return "IdentityPasswordChangeRequest[REDACTED]";
	}

}
