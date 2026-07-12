package com.ixayda.iam.tenant;

public record CreateTenantRequest(String slug, String displayName) {

	public CreateTenantRequest {
		slug = Tenant.validateSlug(slug);
		displayName = Tenant.normalizeDisplayName(displayName);
	}

}
