package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceStateRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "最近查询到的资源版本", minimum = "1") Long version,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityResourceStateRequest[REDACTED]"; }
}
