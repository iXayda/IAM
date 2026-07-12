package com.ixayda.iam.tenant;

import java.util.Objects;

public final class TenantDisabledException extends RuntimeException {

	private final TenantId tenantId;

	public TenantDisabledException(TenantId tenantId) {
		super("Tenant is disabled: " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

}
