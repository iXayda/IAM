package com.ixayda.iam.dto;

import com.ixayda.iam.model.IdentityClient;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityClientSearchRequest(
		@Schema(description = "启用状态，区分大小写：ACTIVE、DISABLED") IdentityClient.Status status,
		@Schema(description = "每页数量", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页返回的 nextCursor，保持状态筛选相同") String cursor) { }
