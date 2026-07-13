package com.ixayda.iam.organization;

import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface OrganizationMembershipOperations {

	OrganizationMembership addMember(TenantId tenantId, OrganizationId organizationId, UserId userId);

	OrganizationMembership removeMember(TenantId tenantId, OrganizationId organizationId, UserId userId);

	/**
	 * Returns the stored relationship without evaluating tenant, organization, user,
	 * or membership activity. Presence must not be used as an authorization decision.
	 */
	Optional<OrganizationMembership> findMembership(TenantId tenantId, OrganizationId organizationId, UserId userId);

	/**
	 * Performs a non-locking eligibility check across the tenant, organization, user,
	 * and membership. The result may become stale immediately; write flows must
	 * acquire the corresponding write guards and revalidate.
	 */
	OrganizationMembership requireActiveMember(TenantId tenantId, OrganizationId organizationId, UserId userId);

}
