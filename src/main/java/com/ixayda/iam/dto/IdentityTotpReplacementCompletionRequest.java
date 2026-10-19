package com.ixayda.iam.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpReplacementCompletionRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "开始更换时取得的更换标识，使用完整 UUID") UUID replacementId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "开始更换时一次性交付的凭据，原样提交", pattern = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", writeOnly = true) String token,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "新认证器当前验证码", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityTotpReplacementCompletionRequest[REDACTED]"; }

}
