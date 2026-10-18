package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

/** A single delivery response; it must not be logged or retained by the identity frontend. */
public record IdentityUserSetupResponse(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "凭据绑定的用户标识") UUID userId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次返回的开通秘密，通过已核验渠道交付；不放入 URL、日志或本地存储", minLength = 43, maxLength = 43) String token,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "开通凭据的到期时间") Instant expiresAt) {

	@Override
	public String toString() { return "IdentityUserSetupResponse[userId=" + this.userId + ", token=[REDACTED], expiresAt=" + this.expiresAt + "]"; }

}
