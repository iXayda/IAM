package com.ixayda.iam.tenant;

import java.util.Optional;

public interface TenantOperations {

	Tenant create(CreateTenantRequest request);

	Optional<Tenant> findById(TenantId tenantId);

	Optional<Tenant> findBySlug(String slug);

	Tenant activate(TenantId tenantId);

	Tenant disable(TenantId tenantId);

	Tenant requireActive(TenantId tenantId);

}
