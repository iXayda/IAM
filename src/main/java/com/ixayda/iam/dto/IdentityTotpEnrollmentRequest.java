package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpEnrollmentRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "当前密码，每次开始注册均须重新校验", format = "password", writeOnly = true) String currentPassword) {

	@Override
	public String toString() { return "IdentityTotpEnrollmentRequest[REDACTED]"; }

}
