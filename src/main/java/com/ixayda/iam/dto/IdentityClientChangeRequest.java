package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityClientChangeRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, minimum = "1", description = "最近查询到的客户端版本") long version,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityClientChangeRequest[REDACTED]"; }

}
