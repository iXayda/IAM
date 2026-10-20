package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditEntry;
import com.ixayda.iam.model.SecurityAuditEvent;

import io.swagger.v3.oas.annotations.media.Schema;

public record SecurityAuditEntryResponse(UUID id, SecurityAuditEvent.Action action, SecurityAuditEntry.Outcome outcome,
		@Schema(description = "目标用户；无法确定目标的事件为 null", types = { "string", "null" }, format = "uuid") UUID targetUserId,
		String actor, String source, UUID correlationId, Instant recordedAt,
		@Schema(description = "非用户目标的类型；资源为 RESOURCE，用户事件为 null", types = { "string", "null" }) String targetType,
		@Schema(description = "非用户目标标识；与 targetType 同时为空或同时存在", types = { "string", "null" }, format = "uuid") UUID targetId) { }
