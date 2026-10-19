package com.ixayda.iam.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpRecoveryCompletionRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "开始恢复时取得的恢复标识，使用完整 UUID") UUID recoveryId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "开始恢复时一次性交付的凭据，原样提交", pattern = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", writeOnly = true) String token,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "新认证器当前验证码", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityTotpRecoveryCompletionRequest[REDACTED]"; }

}
