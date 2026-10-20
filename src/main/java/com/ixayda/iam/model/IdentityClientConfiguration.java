package com.ixayda.iam.model;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Public client configuration, independent of protocol serialization and stored credentials. */
public record IdentityClientConfiguration(String displayName, UUID resourceId, List<String> redirectUris,
		Set<String> scopes, Set<UUID> allowedRoleIds) {

	public IdentityClientConfiguration {
		redirectUris = List.copyOf(redirectUris);
		scopes = Set.copyOf(scopes);
		allowedRoleIds = Set.copyOf(allowedRoleIds);
	}

}
