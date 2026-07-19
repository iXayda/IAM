package com.ixayda.iam.admin;

import com.ixayda.iam.tenant.TenantId;

public final class AdminRoleBootstrapUnavailableException extends RuntimeException {

	private final TenantId tenantId;

	public AdminRoleBootstrapUnavailableException(TenantId tenantId) {
		super("Administrator bootstrap is no longer available for this tenant");
		this.tenantId = tenantId;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

}
