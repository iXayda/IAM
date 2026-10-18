package com.ixayda.iam.dto;

import com.ixayda.iam.model.IdentityUser;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserSearchRequest(@Schema(description = "账号或显示名关键词，按 NFC 规范化；忽略账号大小写，按文字匹配而非 SQL 通配符") String keyword,
		@Schema(description = "账号状态，区分大小写：PENDING、ACTIVE、DISABLED") IdentityUser.Status status,
		@Schema(description = "每页数量", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页返回的 nextCursor；必须沿用原 keyword 和 status") String cursor) { }
