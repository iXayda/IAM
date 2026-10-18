package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityAdministratorAuthenticationRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "当前认证器的六位 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityAdministratorAuthenticationRequest[REDACTED]"; }

}
