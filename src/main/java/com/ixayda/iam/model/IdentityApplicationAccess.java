package com.ixayda.iam.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Effective application roles and their exact subject, client, resource and assignment versions. */
public record IdentityApplicationAccess(UUID userId, UUID clientId, UUID resourceId, String audience,
		long credentialVersion, long clientVersion, long resourceVersion, long assignmentVersion, List<Role> roles) {

	public IdentityApplicationAccess {
		Objects.requireNonNull(userId); Objects.requireNonNull(clientId); Objects.requireNonNull(resourceId); Objects.requireNonNull(audience);
		if (credentialVersion < 1 || clientVersion < 1 || resourceVersion < 1 || assignmentVersion < 0) { throw new IllegalArgumentException("Access versions are invalid"); }
		roles = List.copyOf(roles);
		if (roles.size() > 100 || roles.stream().map(Role::id).distinct().count() != roles.size()
				|| roles.stream().map(Role::code).distinct().count() != roles.size()) { throw new IllegalArgumentException("Application role projection is invalid"); }
	}

	@Override
	public String toString() { return "IdentityApplicationAccess[REDACTED]"; }

	public record Role(UUID id, String code, long version) {
		public Role {
			Objects.requireNonNull(id);
			if (code == null || !code.matches("[a-z][a-z0-9_]{0,63}") || version < 1) { throw new IllegalArgumentException("Application role is invalid"); }
		}
	}

}
