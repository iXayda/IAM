package com.ixayda.iam.organization.internal;

import java.util.Objects;

import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

final class OrganizationMembershipAlreadyExistsException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	private final UserId userId;

	OrganizationMembershipAlreadyExistsException(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		super("Organization membership already exists for organization " + organizationId + " and user " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.organizationId = Objects.requireNonNull(organizationId, "Organization ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
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

}
