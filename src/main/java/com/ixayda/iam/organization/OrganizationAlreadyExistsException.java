package com.ixayda.iam.organization;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class OrganizationAlreadyExistsException extends RuntimeException {

	private final TenantId tenantId;

	private final String slug;

	public OrganizationAlreadyExistsException(TenantId tenantId, String slug) {
		super("Organization slug already exists in tenant " + tenantId + ": " + slug);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.slug = Objects.requireNonNull(slug, "Organization slug must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public String slug() {
		return this.slug;
	}

}
