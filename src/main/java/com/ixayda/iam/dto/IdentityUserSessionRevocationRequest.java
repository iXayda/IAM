package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserSessionRevocationRequest(
		@Schema(description = "本次操作的新六位 TOTP", requiredMode = Schema.RequiredMode.REQUIRED, pattern = "[0-9]{6}") String code) {
	@Override public String toString() { return "IdentityUserSessionRevocationRequest[REDACTED]"; }
}
