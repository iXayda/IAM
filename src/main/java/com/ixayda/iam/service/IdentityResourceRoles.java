package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourceRole;
import com.ixayda.iam.model.IdentityResourceRolePage;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityResourceRoleRepository;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Internal role catalog; trusted callers authorize operations and supply audit attribution. */
@Service
public class IdentityResourceRoles {

	private final IdentityResources resources;
	private final IdentityResourceRoleRepository repository;
	private final SecurityAudits audits;

	IdentityResourceRoles(IdentityResources resources, IdentityResourceRoleRepository repository, SecurityAudits audits) {
		this.resources = resources;
		this.repository = repository;
		this.audits = audits;
	}

	@Transactional
	public IdentityResourceRole create(UUID resourceId, String code, String displayName, SecurityAuditContext audit) {
		Assert.notNull(resourceId, "Resource id is required");
		Assert.notNull(audit, "Audit context is required");
		String exactCode = requireCode(code);
		String normalized = normalizeDisplayName(displayName);
		requireActive(this.resources.lockById(resourceId).orElseThrow(() -> new NoSuchElementException("Resource not found")));
		var role = this.repository.create(UUID.randomUUID(), resourceId, exactCode, normalized);
		record(Action.RESOURCE_ROLE_CREATED, role.id(), audit);
		return role;
	}

	public Optional<IdentityResourceRole> findById(UUID id) {
		Assert.notNull(id, "Resource role id is required");
		return this.repository.findById(id);
	}

	public Optional<IdentityResourceRole> findByCode(UUID resourceId, String code) {
		Assert.notNull(resourceId, "Resource id is required");
		return this.repository.findByCode(resourceId, requireCode(code));
	}

	public IdentityResourceRolePage search(UUID resourceId, IdentityResourceRole.Status status, int pageSize, IdentityResourceRolePage.Cursor after) {
		Assert.notNull(resourceId, "Resource id is required");
		if (pageSize < 1 || pageSize > 100) { throw new IllegalArgumentException("Page size must be between 1 and 100"); }
		if (after != null && (!after.resourceId().equals(resourceId) || after.status() != status)) {
			throw new IllegalArgumentException("Cursor resource role filters do not match");
		}
		this.resources.findById(resourceId).orElseThrow(() -> new NoSuchElementException("Resource not found"));
		var rows = this.repository.search(resourceId, status, pageSize + 1, after);
		boolean more = rows.size() > pageSize;
		var items = more ? rows.subList(0, pageSize) : rows;
		var last = more ? items.getLast() : null;
		return new IdentityResourceRolePage(items, more ? new IdentityResourceRolePage.Cursor(last.createdAt(), last.id(), resourceId, status) : null);
	}

	@Transactional
	public IdentityResourceRole updateDisplayName(UUID id, long expectedVersion, String displayName, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		String normalized = normalizeDisplayName(displayName);
		var current = lockCurrent(id, expectedVersion).role();
		if (current.displayName().equals(normalized)) { return current; }
		var changed = this.repository.update(current, normalized, current.status());
		record(Action.RESOURCE_ROLE_UPDATED, id, audit);
		return changed;
	}

	@Transactional
	public IdentityResourceRole setEnabled(UUID id, long expectedVersion, boolean enabled, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var locked = lockCurrent(id, expectedVersion);
		if (enabled) { requireActive(locked.resource()); }
		var current = locked.role();
		var next = enabled ? IdentityResourceRole.Status.ACTIVE : IdentityResourceRole.Status.DISABLED;
		if (current.status() == next) { return current; }
		var changed = this.repository.update(current, current.displayName(), next);
		record(enabled ? Action.RESOURCE_ROLE_ENABLED : Action.RESOURCE_ROLE_DISABLED, id, audit);
		return changed;
	}

	private LockedRole lockCurrent(UUID id, long expectedVersion) {
		Assert.notNull(id, "Resource role id is required");
		if (expectedVersion < 1) { throw new IllegalArgumentException("Resource role version must be positive"); }
		// The hint's parent is immutable. All writers lock the parent before the role.
		var hint = this.repository.findById(id).orElseThrow(() -> new NoSuchElementException("Resource role not found"));
		var resource = this.resources.lockById(hint.resourceId()).orElseThrow(() -> new NoSuchElementException("Resource not found"));
		var current = this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("Resource role not found"));
		if (current.version() != expectedVersion) { throw new OptimisticLockingFailureException("Resource role version is stale"); }
		return new LockedRole(resource, current);
	}

	static String requireCode(String code) {
		if (code == null || !code.matches("[a-z][a-z0-9_]{0,63}")) {
			throw new IllegalArgumentException("Role code requires 1 to 64 lowercase ASCII letters, digits or underscores, starting with a letter");
		}
		return code;
	}

	static String normalizeDisplayName(String displayName) {
		return IdentityDisplayNames.normalize(displayName, "Resource role display name is invalid");
	}

	private static void requireActive(IdentityResource resource) {
		if (resource.status() != IdentityResource.Status.ACTIVE) { throw new ResourceInactiveException(); }
	}

	private void record(Action action, UUID id, SecurityAuditContext audit) {
		this.audits.recordTargetSuccess(action, new SecurityAuditTarget(SecurityAuditTarget.Type.ROLE, id), audit);
	}

	private record LockedRole(IdentityResource resource, IdentityResourceRole role) { }

	public static final class ResourceInactiveException extends IllegalStateException {
		ResourceInactiveException() { super("An active resource is required"); }
	}

}
