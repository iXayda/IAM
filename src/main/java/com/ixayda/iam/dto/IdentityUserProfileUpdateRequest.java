package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserProfileUpdateRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "显示名，NFC 后为 1 至 128 个 Unicode 码点，不得全为空白或包含控制字符") String displayName,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次资料修改的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityUserProfileUpdateRequest[REDACTED]"; }

}
