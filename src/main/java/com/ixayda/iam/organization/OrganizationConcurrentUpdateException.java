package com.ixayda.iam.organization;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class OrganizationConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	private final long expectedVersion;

	public OrganizationConcurrentUpdateException(TenantId tenantId, OrganizationId organizationId,
			long expectedVersion) {
		super("Organization was updated concurrently: " + organizationId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.organizationId = Objects.requireNonNull(organizationId, "Organization ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected organization version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public OrganizationId organizationId() {
		return this.organizationId;
	}

	public long expectedVersion() {
		return this.expectedVersion;
	}

}
