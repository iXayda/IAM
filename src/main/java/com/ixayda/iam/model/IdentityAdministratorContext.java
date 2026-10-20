package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** Current authentication evidence supplied only by a trusted administrator adapter. */
public record IdentityAdministratorContext(UUID actorId, String sessionId, long credentialVersion,
		long authenticatedAt, IdentityAdministratorAuthentication management, TotpAuthenticationContext authentication) {

	public IdentityAdministratorContext {
		Objects.requireNonNull(actorId, "Administrator identity is required");
		Objects.requireNonNull(authentication, "Trusted authentication attribution is required");
		if (sessionId == null || sessionId.isBlank()) { throw new IllegalArgumentException("Administrator session is required"); }
	}

	@Override
	public String toString() { return "IdentityAdministratorContext[REDACTED]"; }
}
