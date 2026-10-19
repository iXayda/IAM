package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpRecoveryRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本人当前密码，每次开始恢复均须重新校验", format = "password", writeOnly = true) String currentPassword,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本人一个未使用的 MFA 恢复码，按交付格式原样提交", pattern = "^[0-9a-f]{4}(-[0-9a-f]{4}){7}$", writeOnly = true) String recoveryCode) {

	@Override
	public String toString() { return "IdentityTotpRecoveryRequest[REDACTED]"; }

}
