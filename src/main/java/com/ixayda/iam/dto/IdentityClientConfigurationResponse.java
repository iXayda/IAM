package com.ixayda.iam.dto;

import java.util.List;
import java.util.UUID;

public record IdentityClientConfigurationResponse(String displayName, UUID resourceId, List<String> redirectUris,
		List<String> scopes, List<UUID> allowedRoleIds) {

	public IdentityClientConfigurationResponse {
		redirectUris = List.copyOf(redirectUris);
		scopes = List.copyOf(scopes);
		allowedRoleIds = List.copyOf(allowedRoleIds);
	}

}
