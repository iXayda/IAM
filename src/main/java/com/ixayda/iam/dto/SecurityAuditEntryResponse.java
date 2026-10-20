package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditEntry;
import com.ixayda.iam.model.SecurityAuditEvent;

import io.swagger.v3.oas.annotations.media.Schema;

public record SecurityAuditEntryResponse(UUID id, SecurityAuditEvent.Action action, SecurityAuditEntry.Outcome outcome,
		@Schema(description = "目标用户；仅涉及对象或无法确定用户时为 null", types = { "string", "null" }, format = "uuid") UUID targetUserId,
		String actor, String source, UUID correlationId, Instant recordedAt,
		@Schema(description = "对象目标类型：资源为 RESOURCE、角色为 ROLE、客户端为 CLIENT、应用授权为 AUTHORIZATION、浏览器会话为 BROWSER_SESSION、签名密钥为 SIGNING_KEY；不涉及对象时为 null", types = { "string", "null" }) String targetType,
		@Schema(description = "非用户目标标识；与 targetType 同时为空或同时存在", types = { "string", "null" }, format = "uuid") UUID targetId) { }
