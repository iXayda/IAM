package com.ixayda.iam.client.internal;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientSecretMetadata;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.CreateClientRequest;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class ClientWriter {

	private final JdbcOAuthClientRepository repository;

	private final TenantOperations tenants;

	private final ClientSecretProperties properties;

	private final ClientTimeSource timeSource;

	ClientWriter(JdbcOAuthClientRepository repository, TenantOperations tenants, ClientSecretProperties properties,
			ClientTimeSource timeSource) {
		this.repository = repository;
		this.tenants = tenants;
		this.properties = properties;
		this.timeSource = timeSource;
	}

	@Transactional
	OAuthClient store(TenantId tenantId, CreateClientRequest request, String encodedSecret) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(request, "Create client request must not be null");
		boolean confidential = request.type() == ClientType.CONFIDENTIAL;
		if (confidential != (encodedSecret != null)) {
			throw new IllegalArgumentException("Encoded client secret must match the requested client type");
		}

		this.tenants.requireActiveForWrite(tenantId);
		Instant now = this.timeSource.now();
		ClientSecretMetadata secretMetadata = confidential
				? new ClientSecretMetadata(now, this.properties.expirationFrom(now)) : null;
		OAuthClient client = OAuthClient.create(ClientId.random(), tenantId, request, secretMetadata, now);
		return this.repository.insert(new StoredOAuthClient(client, encodedSecret)).client();
	}

}
