package com.ixayda.iam.tenant;

import java.util.Objects;

public final class TenantConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final long expectedVersion;

	public TenantConcurrentUpdateException(TenantId tenantId, long expectedVersion) {
		super("Tenant was updated concurrently: " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected tenant version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public long expectedVersion() {
		return this.expectedVersion;
	}

}
