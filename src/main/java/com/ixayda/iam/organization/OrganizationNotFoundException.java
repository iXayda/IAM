package com.ixayda.iam.organization;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class OrganizationNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	public OrganizationNotFoundException(TenantId tenantId, OrganizationId organizationId) {
		super("Organization not found: " + organizationId);
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
