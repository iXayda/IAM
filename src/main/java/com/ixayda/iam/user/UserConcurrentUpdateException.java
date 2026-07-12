package com.ixayda.iam.user;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class UserConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	private final long expectedVersion;

	public UserConcurrentUpdateException(TenantId tenantId, UserId userId, long expectedVersion) {
		super("User was updated concurrently: " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected user version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public UserId userId() {
		return this.userId;
	}

	public long expectedVersion() {
		return this.expectedVersion;
	}

}
