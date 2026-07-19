package com.ixayda.iam.admin;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface AdminRoleOperations {

	List<AdminRole> findRoles();

	List<AdminRoleBinding> findBindings(TenantId tenantId, UserId userId);

	Optional<AdminRoleBinding> findActiveBinding(TenantId tenantId, UserId userId, AdminRoleCode roleCode);

	Set<AdminPermissionCode> findEffectivePermissions(TenantId tenantId, UserId userId);

	boolean hasPermission(TenantId tenantId, UserId userId, AdminPermissionCode permissionCode);

	AdminRoleBinding bootstrapSuperAdmin(TenantId tenantId, UserId userId);

	AdminRoleBinding grantPermanent(TenantId tenantId, UserId grantedByUserId, UserId userId,
			AdminRoleCode roleCode, String reason);

	AdminRoleBinding grantJustInTime(TenantId tenantId, UserId grantedByUserId, UserId userId,
			AdminRoleCode roleCode, Instant expiresAt, String reason);

	AdminRoleBinding revoke(TenantId tenantId, UserId revokedByUserId, UserId userId,
			AdminRoleCode roleCode);

}
