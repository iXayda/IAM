package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(additionalProperties = Schema.AdditionalPropertiesValue.FALSE, requiredProperties = { "version", "code" })
public record IdentityResourceCredentialChangeRequest(
		@Schema(minimum = "0", description = "最近查询到的校验凭据版本；仅首次轮换可使用 0，禁用必须为正整数") long version,
		@Schema(description = "本次操作的新 TOTP", pattern = "^[0-9]{6}$", writeOnly = true) String code) {

	@Override
	public String toString() { return "IdentityResourceCredentialChangeRequest[REDACTED]"; }

}
