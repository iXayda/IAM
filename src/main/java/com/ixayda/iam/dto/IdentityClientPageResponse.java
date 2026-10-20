package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityClientPageResponse(List<IdentityClientSummaryResponse> items,
		@Schema(description = "下一页游标；为 null 时结束。不能改变状态筛选", types = { "string", "null" }) String nextCursor) {

	public IdentityClientPageResponse { items = List.copyOf(items); }

}
