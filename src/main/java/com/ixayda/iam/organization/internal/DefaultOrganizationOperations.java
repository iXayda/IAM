package com.ixayda.iam.organization.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.organization.CreateOrganizationRequest;
import com.ixayda.iam.organization.Organization;
import com.ixayda.iam.organization.OrganizationConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationDisabledException;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationNotFoundException;
import com.ixayda.iam.organization.OrganizationOperations;
import com.ixayda.iam.organization.OrganizationStatus;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultOrganizationOperations implements OrganizationOperations {

	private final JdbcOrganizationRepository repository;

	private final TenantOperations tenants;

	private final OrganizationTimeSource timeSource;

	DefaultOrganizationOperations(JdbcOrganizationRepository repository, TenantOperations tenants,
			OrganizationTimeSource timeSource) {
		this.repository = repository;
		this.tenants = tenants;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional
	public Organization create(TenantId tenantId, CreateOrganizationRequest request) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(request, "Create organization request must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		Instant now = this.timeSource.now();
		Organization organization = new Organization(OrganizationId.random(), tenantId, request.slug(),
				request.displayName(), OrganizationStatus.ACTIVE, 0, now, now);
		return this.repository.insert(organization);
	}

	@Override
	public Optional<Organization> findById(TenantId tenantId, OrganizationId organizationId) {
		return this.repository.findById(tenantId, organizationId);
	}

	@Override
	public Optional<Organization> findBySlug(TenantId tenantId, String slug) {
		return this.repository.findBySlug(tenantId, slug);
	}

	@Override
	public Organization requireActive(TenantId tenantId, OrganizationId organizationId) {
		this.tenants.requireActive(tenantId);
		return requireActive(requireOrganization(tenantId, organizationId));
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = { TenantDisabledException.class, TenantNotFoundException.class,
					OrganizationDisabledException.class, OrganizationNotFoundException.class })
	public Organization requireActiveForWrite(TenantId tenantId, OrganizationId organizationId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(organizationId, "Organization ID must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		Organization organization = this.repository.findByIdForShare(tenantId, organizationId)
			.orElseThrow(() -> new OrganizationNotFoundException(tenantId, organizationId));
		return requireActive(organization);
	}

	@Override
	@Transactional
	public Organization activate(TenantId tenantId, OrganizationId organizationId) {
		this.tenants.requireActiveForWrite(tenantId);
		Organization current = requireOrganization(tenantId, organizationId);
		Organization changed = current.activate(transitionTime(current));
		return changed == current ? current : updateStatus(current, changed);
	}

	@Override
	@Transactional
	public Organization disable(TenantId tenantId, OrganizationId organizationId) {
		this.tenants.requireActiveForWrite(tenantId);
		Organization current = requireOrganization(tenantId, organizationId);
		Organization changed = current.disable(transitionTime(current));
		return changed == current ? current : updateStatus(current, changed);
	}

	private Organization updateStatus(Organization current, Organization changed) {
		try {
			return this.repository.updateStatus(current, changed);
		}
		catch (OrganizationConcurrentUpdateException ex) {
			Organization latest = requireOrganization(current.tenantId(), current.id());
			if (latest.status() == changed.status()) {
				return latest;
			}
			throw ex;
		}
	}

	private Instant transitionTime(Organization current) {
		Instant now = this.timeSource.now();
		return now.isBefore(current.updatedAt()) ? current.updatedAt() : now;
	}

	private Organization requireOrganization(TenantId tenantId, OrganizationId organizationId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(organizationId, "Organization ID must not be null");
		return this.repository.findById(tenantId, organizationId)
			.orElseThrow(() -> new OrganizationNotFoundException(tenantId, organizationId));
	}

	private Organization requireActive(Organization organization) {
		if (!organization.isActive()) {
			throw new OrganizationDisabledException(organization.tenantId(), organization.id());
		}
		return organization;
	}

}
