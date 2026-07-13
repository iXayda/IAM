package com.ixayda.iam.organization;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public final class OrganizationMembershipNotActiveException extends RuntimeException {

	private final TenantId tenantId;

	private final OrganizationId organizationId;

	private final UserId userId;

	private final OrganizationMembershipStatus status;

	public OrganizationMembershipNotActiveException(TenantId tenantId, OrganizationId organizationId, UserId userId,
			OrganizationMembershipStatus status) {
		super("Organization membership is not active for organization " + organizationId + " and user " + userId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.organizationId = Objects.requireNonNull(organizationId, "Organization ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		this.status = Objects.requireNonNull(status, "Organization membership status must not be null");
		if (status == OrganizationMembershipStatus.ACTIVE) {
			throw new IllegalArgumentException("Active organization membership must not be reported as inactive");
		}
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

	public OrganizationMembershipStatus status() {
		return this.status;
	}

}
