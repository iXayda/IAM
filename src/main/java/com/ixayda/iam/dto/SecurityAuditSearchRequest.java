package com.ixayda.iam.dto;

import com.ixayda.iam.model.SecurityAuditEntry;
import com.ixayda.iam.model.SecurityAuditEvent;

import io.swagger.v3.oas.annotations.media.Schema;

public record SecurityAuditSearchRequest(
		@Schema(description = "记录时间下界，包含；ISO 8601 时间，必须携带时区", format = "date-time") String from,
		@Schema(description = "记录时间上界，不包含；须晚于 from", format = "date-time") String until,
		@Schema(description = "事件动作，区分大小写，使用枚举原名") SecurityAuditEvent.Action action,
		@Schema(description = "事件结果，区分大小写：SUCCESS、FAILURE") SecurityAuditEntry.Outcome outcome,
		@Schema(description = "操作者，精确匹配", maxLength = 128) String actor,
		@Schema(description = "可信入口来源，精确匹配", maxLength = 64) String source,
		@Schema(description = "目标用户完整 UUID，精确匹配", format = "uuid") String targetUserId,
		@Schema(description = "关联标识完整 UUID，精确匹配", format = "uuid") String correlationId,
		@Schema(description = "每页数量", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页 nextCursor；须沿用原筛选条件，可调整 pageSize", maxLength = 1024) String cursor) { }
