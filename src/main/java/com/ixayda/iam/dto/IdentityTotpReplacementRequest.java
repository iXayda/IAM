package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpReplacementRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本人当前密码，每次开始更换均须重新校验", format = "password", writeOnly = true) String currentPassword,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "旧认证器的新验证码", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityTotpReplacementRequest[REDACTED]"; }

}
