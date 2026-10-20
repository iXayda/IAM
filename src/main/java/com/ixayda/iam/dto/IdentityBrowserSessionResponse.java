package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityBrowserSessionResponse(
		@Schema(description = "独立管理 UUID，不是 Cookie 值；MFA 轮换 Cookie 后保持稳定") UUID id,
		Instant createdAt, Instant authenticatedAt, Instant lastAccessedAt, Instant idleExpiresAt, Instant absoluteExpiresAt,
		@Schema(description = "是否是当前调用者携带的浏览器会话") boolean current) { }
