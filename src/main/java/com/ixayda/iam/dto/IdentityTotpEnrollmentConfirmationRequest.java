package com.ixayda.iam.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpEnrollmentConfirmationRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "同一会话开始注册时取得的因素标识，使用完整 UUID") UUID factorId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "新认证器当前验证码", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityTotpEnrollmentConfirmationRequest[REDACTED]"; }

}
