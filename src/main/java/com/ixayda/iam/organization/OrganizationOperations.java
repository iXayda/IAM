package com.ixayda.iam.organization;

import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;

public interface OrganizationOperations {

	Organization create(TenantId tenantId, CreateOrganizationRequest request);

	Optional<Organization> findById(TenantId tenantId, OrganizationId organizationId);

	Optional<Organization> findBySlug(TenantId tenantId, String slug);

	Organization activate(TenantId tenantId, OrganizationId organizationId);

	Organization disable(TenantId tenantId, OrganizationId organizationId);

	Organization requireActive(TenantId tenantId, OrganizationId organizationId);

	/**
	 * Requires an active organization and holds a shared row lock for a write
	 * coordinated by the caller's existing read-write transaction.
	 */
	Organization requireActiveForWrite(TenantId tenantId, OrganizationId organizationId);

}
