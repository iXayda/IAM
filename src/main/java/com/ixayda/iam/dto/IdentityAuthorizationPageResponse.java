package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityAuthorizationPageResponse(List<IdentityAuthorizationResponse> items,
		@Schema(description = "后续页游标，结束为 null", types = { "string", "null" }) String nextCursor) {
	public IdentityAuthorizationPageResponse { items = List.copyOf(items); }
}
