package com.ixayda.iam.organization.internal;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.organization.Organization;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationMembership;
import com.ixayda.iam.organization.OrganizationMembershipConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationMembershipNotActiveException;
import com.ixayda.iam.organization.OrganizationMembershipNotFoundException;
import com.ixayda.iam.organization.OrganizationMembershipOperations;
import com.ixayda.iam.organization.OrganizationOperations;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultOrganizationMembershipOperations implements OrganizationMembershipOperations {

	private final JdbcOrganizationMembershipRepository repository;

	private final TenantOperations tenants;

	private final OrganizationOperations organizations;

	private final UserOperations users;

	private final OrganizationMembershipTimeSource timeSource;

	DefaultOrganizationMembershipOperations(JdbcOrganizationMembershipRepository repository, TenantOperations tenants,
			OrganizationOperations organizations, UserOperations users, OrganizationMembershipTimeSource timeSource) {
		this.repository = repository;
		this.tenants = tenants;
		this.organizations = organizations;
		this.users = users;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional
	public OrganizationMembership addMember(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		requireKey(tenantId, organizationId, userId);
		Organization organization = this.organizations.requireActiveForWrite(tenantId, organizationId);
		User user = this.users.requireActiveForWrite(tenantId, userId);
		requireExpectedParents(tenantId, organizationId, userId, organization, user);

		OrganizationMembership current = this.repository.find(tenantId, organizationId, userId).orElse(null);
		if (current == null) {
			OrganizationMembership initial = OrganizationMembership.active(tenantId, organizationId, userId,
					this.timeSource.now());
			try {
				return this.repository.insert(initial);
			}
			catch (OrganizationMembershipAlreadyExistsException ex) {
				current = requireMembership(tenantId, organizationId, userId);
			}
		}
		return activate(current);
	}

	@Override
	@Transactional
	public OrganizationMembership removeMember(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		requireKey(tenantId, organizationId, userId);
		Tenant tenant = this.tenants.requireActiveForWrite(tenantId);
		if (!tenant.id().equals(tenantId)) {
			throw new IllegalStateException("Membership tenant guard returned a different tenant");
		}
		OrganizationMembership current = requireMembership(tenantId, organizationId, userId);
		if (!current.isActive()) {
			return current;
		}

		OrganizationMembership changed = current.remove(this.timeSource.now());
		try {
			return this.repository.update(current, changed);
		}
		catch (OrganizationMembershipConcurrentUpdateException ex) {
			OrganizationMembership latest = requireMembership(tenantId, organizationId, userId);
			if (!latest.isActive()) {
				return latest;
			}
			throw ex;
		}
	}

	@Override
	public Optional<OrganizationMembership> findMembership(TenantId tenantId, OrganizationId organizationId,
			UserId userId) {
		requireKey(tenantId, organizationId, userId);
		return this.repository.find(tenantId, organizationId, userId);
	}

	@Override
	public OrganizationMembership requireActiveMember(TenantId tenantId, OrganizationId organizationId,
			UserId userId) {
		requireKey(tenantId, organizationId, userId);
		Organization organization = this.organizations.requireActive(tenantId, organizationId);
		User user = this.users.requireActive(tenantId, userId);
		requireExpectedParents(tenantId, organizationId, userId, organization, user);
		OrganizationMembership membership = requireMembership(tenantId, organizationId, userId);
		if (!membership.isActive()) {
			throw new OrganizationMembershipNotActiveException(tenantId, organizationId, userId, membership.status());
		}
		return membership;
	}

	private OrganizationMembership activate(OrganizationMembership current) {
		if (current.isActive()) {
			return current;
		}
		OrganizationMembership changed = current.activate(this.timeSource.now());
		try {
			return this.repository.update(current, changed);
		}
		catch (OrganizationMembershipConcurrentUpdateException ex) {
			OrganizationMembership latest = requireMembership(current.tenantId(), current.organizationId(),
					current.userId());
			if (latest.isActive()) {
				return latest;
			}
			throw ex;
		}
	}

	private OrganizationMembership requireMembership(TenantId tenantId, OrganizationId organizationId,
			UserId userId) {
		return this.repository.find(tenantId, organizationId, userId)
			.orElseThrow(() -> new OrganizationMembershipNotFoundException(tenantId, organizationId, userId));
	}

	private static void requireKey(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(organizationId, "Organization ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static void requireExpectedParents(TenantId tenantId, OrganizationId organizationId, UserId userId,
			Organization organization, User user) {
		if (!organization.tenantId().equals(tenantId) || !organization.id().equals(organizationId)
				|| !user.tenantId().equals(tenantId) || !user.id().equals(userId)) {
			throw new IllegalStateException("Membership lifecycle guards returned a different organization or user");
		}
	}

}
