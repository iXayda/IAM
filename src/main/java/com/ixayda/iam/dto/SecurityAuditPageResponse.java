package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record SecurityAuditPageResponse(List<SecurityAuditEntryResponse> items,
		@Schema(description = "下一页游标；尾页和空页为 null", types = { "string", "null" }) String nextCursor) {

	public SecurityAuditPageResponse {
		items = List.copyOf(items);
	}

}
