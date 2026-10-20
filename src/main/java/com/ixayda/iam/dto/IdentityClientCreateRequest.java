package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityClientCreateRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED) IdentityClientConfigurationRequest configuration,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityClientCreateRequest[REDACTED]"; }

}
