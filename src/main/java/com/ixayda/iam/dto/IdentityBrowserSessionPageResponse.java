package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityBrowserSessionPageResponse(List<IdentityBrowserSessionResponse> items,
		@Schema(description = "后续页游标，结束时为 null；过滤已过绝对期限的记录后可能为空页，请按游标继续", types = { "string", "null" }) String nextCursor) {
	public IdentityBrowserSessionPageResponse { items = List.copyOf(items); }
}
