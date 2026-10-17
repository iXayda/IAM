package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityCsrfResponse(
		@Schema(description = "提交 CSRF 令牌的请求头名称", example = "X-CSRF-TOKEN", requiredMode = Schema.RequiredMode.REQUIRED) String headerName,
		@Schema(description = "当前会话的 CSRF 令牌", example = "<csrf-token>", requiredMode = Schema.RequiredMode.REQUIRED) String token) {
}
