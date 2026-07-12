package com.ixayda.iam.tenant;

import java.util.Objects;

public final class TenantNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	public TenantNotFoundException(TenantId tenantId) {
		super("Tenant not found: " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

}
