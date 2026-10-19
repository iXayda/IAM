package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityMfaRecoveryCodeIssueRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次生成操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityMfaRecoveryCodeIssueRequest[REDACTED]"; }

}
