package com.ixayda.iam.authorization;

import java.security.Principal;
import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record AuthorizationPrincipal(TenantId tenantId, UserId userId, SessionId sessionId,
		SessionAuthenticationMethod authenticationMethod, Instant authenticatedAt) implements Principal {

	public AuthorizationPrincipal {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(sessionId, "Session ID must not be null");
		Objects.requireNonNull(authenticationMethod, "Authentication method must not be null");
		Objects.requireNonNull(authenticatedAt, "Authentication time must not be null");
	}

	@Override
	public String getName() {
		return this.userId.toString();
	}

}
