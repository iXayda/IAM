package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserCreateRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "3 至 64 位 ASCII 字母、数字、点、下划线或连字符，统一为小写") String username,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "显示名，NFC 后为 1 至 128 个 Unicode 码点，不能全为空白或包含控制字符") String displayName,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次创建操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityUserCreateRequest[REDACTED]"; }

}
