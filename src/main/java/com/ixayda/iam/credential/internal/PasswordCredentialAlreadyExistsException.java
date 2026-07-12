package com.ixayda.iam.credential.internal;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

final class PasswordCredentialAlreadyExistsException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	PasswordCredentialAlreadyExistsException(TenantId tenantId, UserId userId) {
		super("Password credential already exists for user: " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	UserId userId() {
		return this.userId;
	}

}
