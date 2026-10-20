package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceRoleCreateRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "1 至 64 个小写 ASCII 字母、数字或下划线，以字母开头；创建后不可改变", pattern = "^[a-z][a-z0-9_]{0,63}$") String roleCode,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "NFC 后为 1 至 128 个 Unicode 码点，不能全为空白或包含控制字符") String displayName,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityResourceRoleCreateRequest[REDACTED]"; }
}
