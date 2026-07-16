package com.ixayda.iam.client;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class ClientConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final ClientId clientId;

	private final long expectedVersion;

	public ClientConcurrentUpdateException(TenantId tenantId, ClientId clientId, long expectedVersion) {
		super("OAuth client changed concurrently");
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.clientId = Objects.requireNonNull(clientId, "Client ID must not be null");
		this.expectedVersion = expectedVersion;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public ClientId clientId() {
		return this.clientId;
	}

	public long expectedVersion() {
		return this.expectedVersion;
	}

}
