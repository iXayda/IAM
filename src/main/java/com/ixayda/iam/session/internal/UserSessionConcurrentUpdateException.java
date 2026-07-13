package com.ixayda.iam.session.internal;

import java.util.Objects;

import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;

final class UserSessionConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final SessionId sessionId;

	private final long expectedVersion;

	UserSessionConcurrentUpdateException(TenantId tenantId, SessionId sessionId, long expectedVersion) {
		super("User session changed concurrently: " + sessionId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.sessionId = Objects.requireNonNull(sessionId, "Session ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected user session version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	SessionId sessionId() {
		return this.sessionId;
	}

	long expectedVersion() {
		return this.expectedVersion;
	}

}
