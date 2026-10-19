package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityPasswordRecoveryCompletionRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "凭据绑定的完整用户 UUID") String userId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "人工交付的密码恢复凭据，原样提交", minLength = 43, maxLength = 43, writeOnly = true) String token,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "新密码；NFC 规范化后 15 至 256 个 Unicode 码点，须通过弱密码检查且不得与当前密码相同", format = "password", writeOnly = true) String newPassword) {

	@Override
	public String toString() { return "IdentityPasswordRecoveryCompletionRequest[REDACTED]"; }

}
