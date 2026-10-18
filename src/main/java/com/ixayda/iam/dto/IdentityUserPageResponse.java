package com.ixayda.iam.dto;

import java.util.List;

public record IdentityUserPageResponse(List<IdentityUserResponse> items, String nextCursor) {

	public IdentityUserPageResponse {
		items = List.copyOf(items);
	}

}
