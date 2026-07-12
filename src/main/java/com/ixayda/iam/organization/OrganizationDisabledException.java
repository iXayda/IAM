package com.ixayda.iam.organization;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class OrganizationDisabledException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	public OrganizationDisabledException(TenantId tenantId, OrganizationId organizationId) {
		super("Organization is disabled: " + organizationId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.organizationId = Objects.requireNonNull(organizationId, "Organization ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public OrganizationId organizationId() {
		return this.organizationId;
	}

}
