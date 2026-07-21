package com.ixayda.iam.admin.internal;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.admin.AdminPermissionCode;
import com.ixayda.iam.admin.AdminRole;
import com.ixayda.iam.admin.AdminRoleAlreadyBoundException;
import com.ixayda.iam.admin.AdminRoleBinding;
import com.ixayda.iam.admin.AdminRoleBindingNotFoundException;
import com.ixayda.iam.admin.AdminRoleBootstrapUnavailableException;
import com.ixayda.iam.admin.AdminRoleCode;
import com.ixayda.iam.admin.AdminRoleGrantDeniedException;
import com.ixayda.iam.admin.AdminRoleNotFoundException;
import com.ixayda.iam.admin.AdminRoleOperations;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultAdminRoleOperations implements AdminRoleOperations {

	private final JdbcAdminRoleRepository repository;

	private final TenantOperations tenants;

	private final UserOperations users;

	private final AdminRoleTimeSource timeSource;

	private final AdminRoleAuditRecorder audit;

	DefaultAdminRoleOperations(JdbcAdminRoleRepository repository, TenantOperations tenants, UserOperations users,
			AdminRoleTimeSource timeSource, AdminRoleAuditRecorder audit) {
		this.repository = repository;
		this.tenants = tenants;
		this.users = users;
		this.timeSource = timeSource;
		this.audit = audit;
	}

	@Override
	public List<AdminRole> findRoles() {
		return this.repository.findRoles();
	}

	@Override
	public List<AdminRoleBinding> findBindings(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		return this.repository.findBindings(tenantId, userId);
	}

	@Override
	public Optional<AdminRoleBinding> findActiveBinding(TenantId tenantId, UserId userId,
			AdminRoleCode roleCode) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(roleCode, "Admin role code must not be null");
		return this.repository.findActiveBinding(tenantId, userId, roleCode);
	}

	@Override
	public Set<AdminPermissionCode> findEffectivePermissions(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		return this.repository.findEffectivePermissions(tenantId, userId, this.timeSource.now());
	}

	@Override
	public boolean hasPermission(TenantId tenantId, UserId userId, AdminPermissionCode permissionCode) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(permissionCode, "Admin permission code must not be null");
		return this.repository.hasPermission(tenantId, userId, permissionCode, this.timeSource.now());
	}

	@Override
	@Transactional
	public AdminRoleBinding bootstrapSuperAdmin(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		this.tenants.requireActiveForExclusiveWrite(tenantId);
		this.users.requireActiveForWrite(tenantId, userId);
		if (this.repository.hasAnyBinding(tenantId)) {
			throw new AdminRoleBootstrapUnavailableException(tenantId);
		}
		requireActiveRole(AdminRoleCode.SUPER_ADMIN);
		AdminRoleBinding binding = this.repository.insert(
				AdminRoleBinding.bootstrap(tenantId, userId, this.timeSource.now()));
		this.audit.granted(binding);
		return binding;
	}

	@Override
	@Transactional
	public AdminRoleBinding grantPermanent(TenantId tenantId, UserId grantedByUserId, UserId userId,
			AdminRoleCode roleCode, String reason) {
		return grant(tenantId, grantedByUserId, userId, roleCode, null, reason);
	}

	@Override
	@Transactional
	public AdminRoleBinding grantJustInTime(TenantId tenantId, UserId grantedByUserId, UserId userId,
			AdminRoleCode roleCode, Instant expiresAt, String reason) {
		Objects.requireNonNull(expiresAt, "JIT admin role expiry must not be null");
		return grant(tenantId, grantedByUserId, userId, roleCode, expiresAt, reason);
	}

	@Override
	@Transactional
	public AdminRoleBinding revoke(TenantId tenantId, UserId revokedByUserId, UserId userId,
			AdminRoleCode roleCode) {
		requireGrantKey(tenantId, revokedByUserId, userId, roleCode);
		this.tenants.requireActiveForExclusiveWrite(tenantId);
		lockActorAndTarget(tenantId, revokedByUserId, userId, false);
		Instant now = this.timeSource.now();
		requireGrantPermission(tenantId, revokedByUserId, roleCode, now);
		AdminRoleBinding current = this.repository.findActiveBinding(tenantId, userId, roleCode)
			.orElseThrow(() -> new AdminRoleBindingNotFoundException(tenantId, userId, roleCode));
		AdminRoleBinding revoked = this.repository.revoke(current, current.revoke(revokedByUserId, now));
		this.audit.revoked(revoked);
		return revoked;
	}

	private AdminRoleBinding grant(TenantId tenantId, UserId grantedByUserId, UserId userId,
			AdminRoleCode roleCode, Instant expiresAt, String reason) {
		requireGrantKey(tenantId, grantedByUserId, userId, roleCode);
		this.tenants.requireActiveForExclusiveWrite(tenantId);
		lockActorAndTarget(tenantId, grantedByUserId, userId, true);
		requireActiveRole(roleCode);
		Instant now = this.timeSource.now();
		requireGrantPermission(tenantId, grantedByUserId, roleCode, now);
		this.repository.findActiveBinding(tenantId, userId, roleCode).ifPresent(current -> {
			if (current.isEffectiveAt(now)) {
				throw new AdminRoleAlreadyBoundException(tenantId, userId, roleCode);
			}
			AdminRoleBinding revoked = this.repository.revoke(current, current.revoke(grantedByUserId, now));
			this.audit.revoked(revoked);
		});
		AdminRoleBinding binding = expiresAt == null
				? AdminRoleBinding.permanent(tenantId, userId, roleCode, grantedByUserId, reason, now)
				: AdminRoleBinding.justInTime(tenantId, userId, roleCode, grantedByUserId, reason, expiresAt,
						now);
		AdminRoleBinding granted = this.repository.insert(binding);
		this.audit.granted(granted);
		return granted;
	}

	private void lockActorAndTarget(TenantId tenantId, UserId actorUserId, UserId userId,
			boolean targetMustBeActive) {
		if (actorUserId.value().compareTo(userId.value()) < 0) {
			this.users.requireActiveForWrite(tenantId, actorUserId);
			requireTargetForWrite(tenantId, userId, targetMustBeActive);
		}
		else {
			requireTargetForWrite(tenantId, userId, targetMustBeActive);
			this.users.requireActiveForWrite(tenantId, actorUserId);
		}
	}

	private void requireTargetForWrite(TenantId tenantId, UserId userId, boolean mustBeActive) {
		if (mustBeActive) {
			this.users.requireActiveForWrite(tenantId, userId);
		}
		else {
			this.users.requireNotDeletedForWrite(tenantId, userId);
		}
	}

	private AdminRole requireActiveRole(AdminRoleCode roleCode) {
		AdminRole role = this.repository.findRole(roleCode).orElseThrow(() -> new AdminRoleNotFoundException(roleCode));
		if (!role.isActive()) {
			throw new AdminRoleNotFoundException(roleCode);
		}
		return role;
	}

	private void requireGrantPermission(TenantId tenantId, UserId actorUserId, AdminRoleCode roleCode,
			Instant evaluatedAt) {
		if (!this.repository.canGrant(tenantId, actorUserId, roleCode, evaluatedAt)) {
			throw new AdminRoleGrantDeniedException(tenantId, actorUserId, roleCode);
		}
	}

	private static void requireKey(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static void requireGrantKey(TenantId tenantId, UserId actorUserId, UserId userId,
			AdminRoleCode roleCode) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(actorUserId, "Admin role actor user ID must not be null");
		Objects.requireNonNull(roleCode, "Admin role code must not be null");
		if (actorUserId.equals(userId)) {
			throw new AdminRoleGrantDeniedException(tenantId, actorUserId, roleCode);
		}
	}

}
