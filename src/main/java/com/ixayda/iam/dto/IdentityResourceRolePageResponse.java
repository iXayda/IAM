package com.ixayda.iam.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceRolePageResponse(List<IdentityResourceRoleResponse> items,
		@Schema(description = "后续页游标，结束时为 null", types = { "string", "null" }) String nextCursor) {
	public IdentityResourceRolePageResponse { items = List.copyOf(items); }
}
