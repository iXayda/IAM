package com.ixayda.iam.client;

import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;

public interface ClientOperations {

	ClientRegistration create(TenantId tenantId, CreateClientRequest request);

	Optional<OAuthClient> findById(TenantId tenantId, ClientId clientId);

	Optional<OAuthClient> findByIdentifier(ClientIdentifier identifier);

	OAuthClient requireActive(TenantId tenantId, ClientId clientId);

	OAuthClient requireActiveForWrite(TenantId tenantId, ClientId clientId);

	OAuthClient activate(TenantId tenantId, ClientId clientId);

	OAuthClient disable(TenantId tenantId, ClientId clientId);

}
