package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourceRole;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserRolePage;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityResourceRoleRepository;
import com.ixayda.iam.repository.IdentityUserRoleRepository;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Internal direct assignments; callers authorize changes and provide trusted attribution. */
@Service
public class IdentityUserRoles {

	private final IdentityUsers users;
	private final IdentityResources resources;
	private final IdentityResourceRoleRepository roles;
	private final IdentityUserRoleRepository repository;
	private final SecurityAudits audits;

	IdentityUserRoles(IdentityUsers users, IdentityResources resources, IdentityResourceRoleRepository roles,
			IdentityUserRoleRepository repository, SecurityAudits audits) {
		this.users = users;
		this.resources = resources;
		this.roles = roles;
		this.repository = repository;
		this.audits = audits;
	}

	@Transactional
	public ChangeResult change(UUID userId, UUID roleId, long expectedVersion, boolean grant, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(roleId, "Resource role id is required");
		Assert.notNull(audit, "Audit context is required");
		if (expectedVersion < 0) { throw new IllegalArgumentException("Assignment version must be nonnegative"); }
		var user = this.users.lockById(userId);
		var hint = this.roles.findById(roleId).orElseThrow(() -> new NoSuchElementException("Resource role not found"));
		var resource = this.resources.lockById(hint.resourceId()).orElseThrow(() -> new NoSuchElementException("Resource not found"));
		var role = this.roles.lockById(roleId).orElseThrow(() -> new NoSuchElementException("Resource role not found"));
		long version = this.repository.version(userId, resource.id());
		if (version != expectedVersion) { throw new OptimisticLockingFailureException("Assignment version is stale"); }
		if (grant && (user.status() == IdentityUser.Status.DISABLED || resource.status() != IdentityResource.Status.ACTIVE
				|| role.status() != IdentityResourceRole.Status.ACTIVE)) { throw new BindingNotAllowedException(); }
		boolean present = this.repository.find(userId, roleId).isPresent();
		if (present == grant) { return new ChangeResult(false, version, resource.id()); }
		long next = this.repository.advanceVersion(userId, resource.id(), expectedVersion);
		if (grant) { this.repository.grant(userId, resource.id(), roleId); }
		else { this.repository.revoke(userId, roleId); }
		this.audits.recordTargetSuccess(grant ? Action.USER_ROLE_GRANTED : Action.USER_ROLE_REVOKED, userId,
				new SecurityAuditTarget(SecurityAuditTarget.Type.ROLE, roleId), audit);
		return new ChangeResult(true, next, resource.id());
	}

	public IdentityUserRolePage search(UUID userId, UUID resourceId, int pageSize, IdentityUserRolePage.Cursor after) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(resourceId, "Resource id is required");
		if (pageSize < 1 || pageSize > 100) { throw new IllegalArgumentException("Page size must be between 1 and 100"); }
		if (after != null && (!after.userId().equals(userId) || !after.resourceId().equals(resourceId))) {
			throw new IllegalArgumentException("Cursor user and resource must match");
		}
		this.users.findById(userId).orElseThrow(() -> new NoSuchElementException("User not found"));
		this.resources.findById(resourceId).orElseThrow(() -> new NoSuchElementException("Resource not found"));
		var snapshot = this.repository.search(userId, resourceId, pageSize + 1, after);
		if (after != null && after.version() != snapshot.version()) { throw new OptimisticLockingFailureException("Assignments changed during pagination"); }
		boolean more = snapshot.items().size() > pageSize;
		var items = more ? snapshot.items().subList(0, pageSize) : snapshot.items();
		var last = more ? items.getLast() : null;
		return new IdentityUserRolePage(items, snapshot.version(), more
				? new IdentityUserRolePage.Cursor(userId, resourceId, snapshot.version(), last.createdAt(), last.roleId()) : null);
	}

	public record ChangeResult(boolean changed, long version, UUID resourceId) { }

	public static final class BindingNotAllowedException extends IllegalStateException {
		BindingNotAllowedException() { super("Active resource and role and a user accepting assignments are required"); }
	}

}
