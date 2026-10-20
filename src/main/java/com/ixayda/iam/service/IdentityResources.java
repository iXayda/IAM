package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourcePage;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityResourceRepository;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.util.Assert;

/** Internal resource operations; the trusted caller authorizes access and supplies audit attribution. */
@Service
public class IdentityResources {

	private final IdentityResourceRepository repository;
	private final SecurityAudits audits;

	IdentityResources(IdentityResourceRepository repository, SecurityAudits audits) {
		this.repository = repository;
		this.audits = audits;
	}

	@Transactional
	public IdentityResource create(String audience, String displayName, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var resource = this.repository.create(UUID.randomUUID(), requireAudience(audience), normalizeDisplayName(displayName));
		record(Action.RESOURCE_CREATED, resource.id(), audit);
		return resource;
	}

	public Optional<IdentityResource> findById(UUID id) {
		Assert.notNull(id, "Resource id is required");
		return this.repository.findById(id);
	}

	public Optional<IdentityResource> findByAudience(String audience) {
		return this.repository.findByAudience(requireAudience(audience));
	}

	public IdentityResourcePage search(IdentityResource.Status status, int pageSize, IdentityResourcePage.Cursor after) {
		if (pageSize < 1 || pageSize > 100) { throw new IllegalArgumentException("Page size must be between 1 and 100"); }
		if (after != null && after.status() != status) { throw new IllegalArgumentException("Cursor resource filters do not match"); }
		var rows = this.repository.search(status, pageSize + 1, after);
		boolean more = rows.size() > pageSize;
		var items = more ? rows.subList(0, pageSize) : rows;
		var last = more ? items.getLast() : null;
		return new IdentityResourcePage(items, more ? new IdentityResourcePage.Cursor(last.createdAt(), last.id(), status) : null);
	}

	@Transactional
	public IdentityResource updateDisplayName(UUID id, long version, String displayName, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		String normalized = normalizeDisplayName(displayName);
		var current = lockCurrent(id, version);
		if (current.displayName().equals(normalized)) { return current; }
		var changed = this.repository.update(current, normalized, current.status());
		record(Action.RESOURCE_UPDATED, id, audit);
		return changed;
	}

	@Transactional
	public IdentityResource setEnabled(UUID id, long version, boolean enabled, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var current = lockCurrent(id, version);
		var next = enabled ? IdentityResource.Status.ACTIVE : IdentityResource.Status.DISABLED;
		if (current.status() == next) { return current; }
		var changed = this.repository.update(current, current.displayName(), next);
		record(enabled ? Action.RESOURCE_ENABLED : Action.RESOURCE_DISABLED, id, audit);
		return changed;
	}

	private IdentityResource lockCurrent(UUID id, long version) {
		Assert.notNull(id, "Resource id is required");
		if (version < 1) { throw new IllegalArgumentException("Resource version must be positive"); }
		var current = this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("Resource not found"));
		if (current.version() != version) { throw new OptimisticLockingFailureException("Resource version is stale"); }
		return current;
	}

	private void record(Action action, UUID id, SecurityAuditContext context) {
		this.audits.recordTargetSuccess(action, new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, id), context);
	}

	static String requireAudience(String audience) {
		if (audience == null || !audience.matches("[\\x21-\\x7e]{1,256}")) {
			throw new IllegalArgumentException("Resource audience requires 1 to 256 visible ASCII characters");
		}
		return audience;
	}

	static String normalizeDisplayName(String value) {
		return IdentityDisplayNames.normalize(value, "Resource display name is invalid");
	}

	/** Parent lock used before role and authorization rows. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityResource> lockById(UUID id) {
		Assert.notNull(id, "Resource id is required");
		return this.repository.lockById(id);
	}

}
