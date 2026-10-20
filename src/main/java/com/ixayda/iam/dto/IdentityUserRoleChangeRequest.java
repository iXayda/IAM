package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserRoleChangeRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "该用户在角色所属资源的绑定版本；首次变更为 0", minimum = "0") Long version,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityUserRoleChangeRequest[REDACTED]"; }

}
