package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

/** Single delivery of the recovery proof and new authenticator material. */
public record IdentityTotpRecoveryResponse(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "待确认恢复标识") UUID recoveryId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次交付的恢复凭据；完成时原样提交", pattern = "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$") String token,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "新因素标识，尚未激活") UUID factorId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次交付的新认证器 Base32 密钥", pattern = "^[A-Z2-7]{32}$") String secret,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次交付的 otpauth 配置 URI；不得作为浏览器导航地址", format = "uri") String provisioningUri,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "恢复凭据与新因素确认的到期时间，有效期十分钟") Instant expiresAt) {

	@Override
	public String toString() { return "IdentityTotpRecoveryResponse[recoveryId=" + this.recoveryId + ", expiresAt=" + this.expiresAt + ", secrets=REDACTED]"; }

}
