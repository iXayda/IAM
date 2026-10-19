package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;

/** Single delivery of secrets; callers must not log or retain the response. */
public record IdentityMfaRecoveryCodesResponse(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "本次恢复码批次") UUID generationId,
		@ArraySchema(minItems = 10, maxItems = 10, arraySchema = @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "仅本次返回的恢复码；离线妥善保管，不放入 URL、日志或浏览器持久存储"), schema = @Schema(type = "string", pattern = "^[0-9a-f]{4}(-[0-9a-f]{4}){7}$")) List<String> codes,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "数据库签发时间") Instant issuedAt) {

	public IdentityMfaRecoveryCodesResponse {
		codes = List.copyOf(codes);
	}

	@Override
	public String toString() { return "IdentityMfaRecoveryCodesResponse[generationId=" + this.generationId + ", codes=REDACTED, issuedAt=" + this.issuedAt + "]"; }

}
