package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

/** Single delivery of enrollment secrets, never a profile or a reusable authentication credential. */
public record IdentityTotpEnrollmentResponse(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "待确认因素标识；确认和取消时原样提交") UUID factorId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次交付的 Base32 认证器密钥", pattern = "^[A-Z2-7]{32}$") String secret,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次交付的 otpauth 配置 URI；不得作为浏览器导航地址", format = "uri") String provisioningUri,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "待确认注册到期时间；有效期十分钟") Instant expiresAt) {

	@Override
	public String toString() { return "IdentityTotpEnrollmentResponse[factorId=" + this.factorId + ", expiresAt=" + this.expiresAt + ", secrets=REDACTED]"; }

}
