package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceCreateRequest(@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "1 至 256 个可见 ASCII 字符，精确匹配且区分大小写，不裁剪") String audience,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "NFC 后为 1 至 128 个 Unicode 码点，不能全为空白或包含控制字符") String displayName,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityResourceCreateRequest[REDACTED]"; }
}
