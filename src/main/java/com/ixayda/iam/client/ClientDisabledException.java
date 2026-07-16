package com.ixayda.iam.client;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class ClientDisabledException extends RuntimeException {

	private final TenantId tenantId;

	private final ClientId clientId;

	public ClientDisabledException(TenantId tenantId, ClientId clientId) {
		super("OAuth client is disabled");
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.clientId = Objects.requireNonNull(clientId, "Client ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public ClientId clientId() {
		return this.clientId;
	}

}
