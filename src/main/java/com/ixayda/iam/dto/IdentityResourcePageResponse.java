package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourcePageResponse(List<IdentityResourceResponse> items,
		@Schema(description = "后续页游标，结束时为 null", types = { "string", "null" }) String nextCursor) {
	public IdentityResourcePageResponse { items = List.copyOf(items); }
}
