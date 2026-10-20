package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAuthorizationSummary;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityAuthorizationResponse(
		@Schema(description = "用于查看及撤销的授权 UUID，不是访问凭据") UUID id,
		UUID clientId, String clientName, UUID resourceId, String resourceName, String audience,
		Instant issuedAt, @Schema(description = "当前授权阶段的到期时间，不延长刷新家族绝对期限") Instant expiresAt,
		Set<String> scopes, @Schema(description = "记录状态，不代替资源在线校验或应用本地会话状态") IdentityAuthorizationSummary.Status status) {
	public IdentityAuthorizationResponse { scopes = Set.copyOf(scopes); }
}
