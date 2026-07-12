package com.ixayda.iam.user;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class UserNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	public UserNotFoundException(TenantId tenantId, UserId userId) {
		super("User not found: " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public UserId userId() {
		return this.userId;
	}

}
