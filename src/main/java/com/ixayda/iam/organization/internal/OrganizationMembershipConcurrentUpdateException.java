package com.ixayda.iam.organization.internal;

import java.util.Objects;

import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

final class OrganizationMembershipConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	private final UserId userId;

	private final long expectedVersion;

	OrganizationMembershipConcurrentUpdateException(TenantId tenantId, OrganizationId organizationId, UserId userId,
			long expectedVersion) {
		super("Organization membership changed concurrently for organization " + organizationId + " and user "
				+ userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.organizationId = Objects.requireNonNull(organizationId, "Organization ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected organization membership version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	OrganizationId organizationId() {
		return this.organizationId;
	}

	UserId userId() {
		return this.userId;
	}

	long expectedVersion() {
		return this.expectedVersion;
	}

}
