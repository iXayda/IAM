package com.ixayda.iam.user;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class UserAlreadyExistsException extends RuntimeException {

	private final TenantId tenantId;

	public UserAlreadyExistsException(TenantId tenantId) {
		super("A user with the same login identifier already exists in tenant " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

}
