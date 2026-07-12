package com.ixayda.iam.organization;

public record CreateOrganizationRequest(String slug, String displayName) {

	public CreateOrganizationRequest {
		slug = Organization.validateSlug(slug);
		displayName = Organization.normalizeDisplayName(displayName);
	}

}
