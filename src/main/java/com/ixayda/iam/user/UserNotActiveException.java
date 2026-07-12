package com.ixayda.iam.user;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class UserNotActiveException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	private final UserStatus status;

	public UserNotActiveException(TenantId tenantId, UserId userId, UserStatus status) {
		super("User is not active: " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		this.status = Objects.requireNonNull(status, "User status must not be null");
		if (status == UserStatus.ACTIVE) {
			throw new IllegalArgumentException("Active user must not be reported as inactive");
		}
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public UserId userId() {
		return this.userId;
	}

	public UserStatus status() {
		return this.status;
	}

}
