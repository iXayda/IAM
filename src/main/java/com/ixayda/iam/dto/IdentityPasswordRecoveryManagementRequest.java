package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityPasswordRecoveryManagementRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次签发或取消操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityPasswordRecoveryManagementRequest[REDACTED]"; }

}
