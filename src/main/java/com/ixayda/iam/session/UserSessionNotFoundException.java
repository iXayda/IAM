package com.ixayda.iam.session;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class UserSessionNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	private final SessionId sessionId;

	public UserSessionNotFoundException(TenantId tenantId, SessionId sessionId) {
		super("User session was not found: " + sessionId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.sessionId = Objects.requireNonNull(sessionId, "Session ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public SessionId sessionId() {
		return this.sessionId;
	}

}
