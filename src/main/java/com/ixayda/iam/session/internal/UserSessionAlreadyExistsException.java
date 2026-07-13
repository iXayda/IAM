package com.ixayda.iam.session.internal;

import java.util.Objects;

import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;

final class UserSessionAlreadyExistsException extends RuntimeException {

	private final TenantId tenantId;

	private final SessionId sessionId;

	UserSessionAlreadyExistsException(TenantId tenantId, SessionId sessionId) {
		super("User session already exists: " + sessionId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.sessionId = Objects.requireNonNull(sessionId, "Session ID must not be null");
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	SessionId sessionId() {
		return this.sessionId;
	}

}
