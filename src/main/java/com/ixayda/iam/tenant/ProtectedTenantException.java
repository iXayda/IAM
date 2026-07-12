package com.ixayda.iam.tenant;

import java.util.Objects;

public final class ProtectedTenantException extends RuntimeException {

	private final TenantId tenantId;

	public ProtectedTenantException(TenantId tenantId) {
		super("Tenant is protected: " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

}
