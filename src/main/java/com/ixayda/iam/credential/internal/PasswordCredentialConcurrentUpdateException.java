package com.ixayda.iam.credential.internal;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

final class PasswordCredentialConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	private final long expectedVersion;

	PasswordCredentialConcurrentUpdateException(TenantId tenantId, UserId userId, long expectedVersion) {
		super("Password credential changed concurrently for user: " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected password credential version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	UserId userId() {
		return this.userId;
	}

	long expectedVersion() {
		return this.expectedVersion;
	}

}
