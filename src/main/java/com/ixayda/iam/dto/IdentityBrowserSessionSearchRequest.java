package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityBrowserSessionSearchRequest(
		@Schema(description = "每页上限", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页的 nextCursor，仅限当前用户") String cursor) { }
