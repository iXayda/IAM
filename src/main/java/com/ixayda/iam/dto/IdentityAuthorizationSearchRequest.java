package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityAuthorizationSearchRequest(
		@Schema(description = "每页数量", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页的 nextCursor，仅限当前用户") String cursor) { }
