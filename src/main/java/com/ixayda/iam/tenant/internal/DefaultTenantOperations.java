package com.ixayda.iam.tenant.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantConcurrentUpdateException;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultTenantOperations implements TenantOperations {

	private final JdbcTenantRepository repository;

	private final TenantTimeSource timeSource;

	DefaultTenantOperations(JdbcTenantRepository repository, TenantTimeSource timeSource) {
		this.repository = repository;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional
	public Tenant create(CreateTenantRequest request) {
		Objects.requireNonNull(request, "Create tenant request must not be null");
		Instant now = this.timeSource.now();
		Tenant tenant = new Tenant(TenantId.random(), request.slug(), request.displayName(), TenantStatus.ACTIVE, 0,
				now, now);
		return this.repository.insert(tenant);
	}

	@Override
	public Optional<Tenant> findById(TenantId tenantId) {
		return this.repository.findById(tenantId);
	}

	@Override
	public Optional<Tenant> findBySlug(String slug) {
		return this.repository.findBySlug(slug);
	}

	@Override
	public Tenant requireActive(TenantId tenantId) {
		Tenant tenant = requireTenant(tenantId);
		return requireActive(tenant);
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public Tenant requireActiveForWrite(TenantId tenantId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Tenant tenant = this.repository.findByIdForShare(tenantId)
			.orElseThrow(() -> new TenantNotFoundException(tenantId));
		return requireActive(tenant);
	}

	private Tenant requireActive(Tenant tenant) {
		if (!tenant.isActive()) {
			throw new TenantDisabledException(tenant.id());
		}
		return tenant;
	}

	@Override
	@Transactional
	public Tenant activate(TenantId tenantId) {
		Tenant current = requireTenant(tenantId);
		Tenant changed = current.activate(transitionTime(current));
		return changed == current ? current : updateStatus(current, changed);
	}

	@Override
	@Transactional
	public Tenant disable(TenantId tenantId) {
		Tenant current = requireTenant(tenantId);
		Tenant changed = current.disable(transitionTime(current));
		return changed == current ? current : updateStatus(current, changed);
	}

	private Tenant updateStatus(Tenant current, Tenant changed) {
		try {
			return this.repository.updateStatus(current, changed);
		}
		catch (TenantConcurrentUpdateException ex) {
			Tenant latest = requireTenant(current.id());
			if (latest.status() == changed.status()) {
				return latest;
			}
			throw ex;
		}
	}

	private Instant transitionTime(Tenant current) {
		Instant now = this.timeSource.now();
		return now.isBefore(current.updatedAt()) ? current.updatedAt() : now;
	}

	private Tenant requireTenant(TenantId tenantId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		return this.repository.findById(tenantId).orElseThrow(() -> new TenantNotFoundException(tenantId));
	}

}
