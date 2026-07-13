package com.ixayda.iam.organization;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public final class OrganizationMembershipNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	private final UserId userId;

	public OrganizationMembershipNotFoundException(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		super("Organization membership not found for organization " + organizationId + " and user " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.organizationId = Objects.requireNonNull(organizationId, "Organization ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public OrganizationId organizationId() {
		return this.organizationId;
	}

	public UserId userId() {
		return this.userId;
	}

}
