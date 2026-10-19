package com.ixayda.iam.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityTotpEnrollmentCancellationRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "同一会话开始注册时取得的待确认因素标识，使用完整 UUID") UUID factorId) {

}
