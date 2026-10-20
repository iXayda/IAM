package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityUserRolePageResponse(List<IdentityUserRoleResponse> items,
		@Schema(description = "该用户在该资源的绑定版本，与当前页使用同一语句快照", minimum = "0") long version,
		@Schema(description = "下一页游标；为 null 时结束。绑定变化后须重新查询第一页", types = { "string", "null" }) String nextCursor) {

	public IdentityUserRolePageResponse { items = List.copyOf(items); }

}
