package com.ixayda.iam.admin.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.ixayda.iam.admin.AdminPermissionCode;
import com.ixayda.iam.admin.AdminRole;
import com.ixayda.iam.admin.AdminRoleAlreadyBoundException;
import com.ixayda.iam.admin.AdminRoleBinding;
import com.ixayda.iam.admin.AdminRoleBindingConcurrentUpdateException;
import com.ixayda.iam.admin.AdminRoleBindingId;
import com.ixayda.iam.admin.AdminRoleBindingStatus;
import com.ixayda.iam.admin.AdminRoleBindingType;
import com.ixayda.iam.admin.AdminRoleCode;
import com.ixayda.iam.admin.AdminRoleStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcAdminRoleRepository {

	private static final String ROLE_COLUMNS =
			"role_code, name, description, status, protected_role, version, created_at, updated_at";

	private static final String BINDING_COLUMNS = "binding_id, tenant_id, user_id, role_code, binding_type, "
			+ "status, created_by_user_id, reason, expires_at, version, created_at, updated_at, "
			+ "revoked_by_user_id, revoked_at";

	private static final RowMapper<AdminRole> ROLE_MAPPER = JdbcAdminRoleRepository::mapRole;

	private static final RowMapper<AdminRoleBinding> BINDING_MAPPER = JdbcAdminRoleRepository::mapBinding;

	private final JdbcClient jdbcClient;

	JdbcAdminRoleRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	List<AdminRole> findRoles() {
		return this.jdbcClient.sql("SELECT " + ROLE_COLUMNS + " FROM admin_roles ORDER BY role_code")
			.query(ROLE_MAPPER)
			.list();
	}

	Optional<AdminRole> findRole(AdminRoleCode roleCode) {
		Objects.requireNonNull(roleCode, "Admin role code must not be null");
		return this.jdbcClient.sql("SELECT " + ROLE_COLUMNS + " FROM admin_roles WHERE role_code = :roleCode")
			.param("roleCode", roleCode.value())
			.query(ROLE_MAPPER)
			.optional();
	}

	List<AdminRoleBinding> findBindings(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		return this.jdbcClient.sql("SELECT " + BINDING_COLUMNS + " FROM admin_role_bindings"
				+ " WHERE tenant_id = :tenantId AND user_id = :userId"
				+ " ORDER BY created_at, binding_id")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(BINDING_MAPPER)
			.list();
	}

	Optional<AdminRoleBinding> findActiveBinding(TenantId tenantId, UserId userId, AdminRoleCode roleCode) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(roleCode, "Admin role code must not be null");
		return this.jdbcClient.sql("SELECT " + BINDING_COLUMNS + " FROM admin_role_bindings"
				+ " WHERE tenant_id = :tenantId AND user_id = :userId"
				+ " AND role_code = :roleCode AND status = 'active'")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("roleCode", roleCode.value())
			.query(BINDING_MAPPER)
			.optional();
	}

	Set<AdminPermissionCode> findEffectivePermissions(TenantId tenantId, UserId userId, Instant evaluatedAt) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(evaluatedAt, "Admin permission evaluation time must not be null");
		return this.jdbcClient.sql("""
				SELECT DISTINCT permissions.permission_code
				FROM tenants
				JOIN users
				  ON users.tenant_id = tenants.tenant_id
				 AND users.user_id = :userId
				 AND users.status = 'active'
				JOIN admin_role_bindings bindings
				  ON bindings.tenant_id = tenants.tenant_id
				 AND bindings.user_id = users.user_id
				 AND bindings.status = 'active'
				 AND (bindings.binding_type = 'permanent' OR bindings.expires_at > :evaluatedAt)
				JOIN admin_roles roles
				  ON roles.role_code = bindings.role_code
				 AND roles.status = 'active'
				JOIN admin_role_permissions role_permissions
				  ON role_permissions.role_code = roles.role_code
				JOIN admin_permissions permissions
				  ON permissions.permission_code = role_permissions.permission_code
				 AND permissions.status = 'active'
				WHERE tenants.tenant_id = :tenantId
				  AND tenants.status = 'active'
				ORDER BY permissions.permission_code
				""")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("evaluatedAt", databaseValue(evaluatedAt))
			.query(String.class)
			.list()
			.stream()
			.map(AdminPermissionCode::from)
			.collect(Collectors.toUnmodifiableSet());
	}

	boolean hasPermission(TenantId tenantId, UserId userId, AdminPermissionCode permissionCode,
			Instant evaluatedAt) {
		Objects.requireNonNull(permissionCode, "Admin permission code must not be null");
		return findEffectivePermissions(tenantId, userId, evaluatedAt).contains(permissionCode);
	}

	boolean canGrant(TenantId tenantId, UserId actorUserId, AdminRoleCode grantedRoleCode, Instant evaluatedAt) {
		requireKey(tenantId, actorUserId);
		Objects.requireNonNull(grantedRoleCode, "Granted admin role code must not be null");
		Objects.requireNonNull(evaluatedAt, "Admin grant evaluation time must not be null");
		return this.jdbcClient.sql("""
				SELECT EXISTS (
				    SELECT 1
				    FROM tenants
				    JOIN users
				      ON users.tenant_id = tenants.tenant_id
				     AND users.user_id = :actorUserId
				     AND users.status = 'active'
				    JOIN admin_role_bindings bindings
				      ON bindings.tenant_id = tenants.tenant_id
				     AND bindings.user_id = users.user_id
				     AND bindings.status = 'active'
				     AND (bindings.binding_type = 'permanent' OR bindings.expires_at > :evaluatedAt)
				    JOIN admin_roles roles
				      ON roles.role_code = bindings.role_code
				     AND roles.status = 'active'
				    JOIN admin_role_permissions role_permissions
				      ON role_permissions.role_code = roles.role_code
				    JOIN admin_permissions permissions
				      ON permissions.permission_code = role_permissions.permission_code
				     AND permissions.permission_code = :assignPermission
				     AND permissions.status = 'active'
				    JOIN admin_role_grant_rules grant_rules
				      ON grant_rules.granter_role_code = roles.role_code
				     AND grant_rules.granted_role_code = :grantedRoleCode
				    WHERE tenants.tenant_id = :tenantId
				      AND tenants.status = 'active'
				)
				""")
			.param("tenantId", tenantId.value())
			.param("actorUserId", actorUserId.value())
			.param("evaluatedAt", databaseValue(evaluatedAt))
			.param("assignPermission", AdminPermissionCode.ASSIGN_ROLES.value())
			.param("grantedRoleCode", grantedRoleCode.value())
			.query(Boolean.class)
			.single();
	}

	boolean hasAnyBinding(TenantId tenantId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		return this.jdbcClient.sql("""
				SELECT EXISTS (
				    SELECT 1 FROM admin_role_bindings WHERE tenant_id = :tenantId
				)
				""")
			.param("tenantId", tenantId.value())
			.query(Boolean.class)
			.single();
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = AdminRoleAlreadyBoundException.class)
	AdminRoleBinding insert(AdminRoleBinding binding) {
		Objects.requireNonNull(binding, "Admin role binding must not be null");
		requireWriteTransaction();
		if (binding.status() != AdminRoleBindingStatus.ACTIVE || binding.version() != 0
				|| !binding.createdAt().equals(binding.updatedAt())) {
			throw new IllegalArgumentException("New admin role binding must be active at version zero");
		}
		int affected = this.jdbcClient.sql("""
				INSERT INTO admin_role_bindings
				    (binding_id, tenant_id, user_id, role_code, binding_type, status,
				     created_by_user_id, reason, expires_at, version, created_at, updated_at)
				VALUES
				    (:bindingId, :tenantId, :userId, :roleCode, :bindingType, 'active',
				     :createdByUserId, :reason, :expiresAt, :version, :createdAt, :updatedAt)
				ON CONFLICT DO NOTHING
				""")
			.param("bindingId", binding.id().value())
			.param("tenantId", binding.tenantId().value())
			.param("userId", binding.userId().value())
			.param("roleCode", binding.roleCode().value())
			.param("bindingType", databaseValue(binding.type()))
			.param("createdByUserId", value(binding.createdByUserId()))
			.param("reason", binding.reason())
			.param("expiresAt", databaseValue(binding.expiresAt()))
			.param("version", binding.version())
			.param("createdAt", databaseValue(binding.createdAt()))
			.param("updatedAt", databaseValue(binding.updatedAt()))
			.update();
		if (affected == 0) {
			throw new AdminRoleAlreadyBoundException(binding.tenantId(), binding.userId(), binding.roleCode());
		}
		if (affected != 1) {
			throw new IllegalStateException("Creating an admin role binding affected an unexpected number of rows: "
					+ affected);
		}
		return binding;
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = AdminRoleBindingConcurrentUpdateException.class)
	AdminRoleBinding revoke(AdminRoleBinding current, AdminRoleBinding changed) {
		Objects.requireNonNull(current, "Current admin role binding must not be null");
		Objects.requireNonNull(changed, "Changed admin role binding must not be null");
		requireWriteTransaction();
		if (!current.id().equals(changed.id()) || current.status() != AdminRoleBindingStatus.ACTIVE
				|| changed.status() != AdminRoleBindingStatus.REVOKED || current.version() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1 || !current.createdAt().equals(changed.createdAt())) {
			throw new IllegalArgumentException("Admin role revocation must preserve identity and advance one version");
		}
		int affected = this.jdbcClient.sql("""
				UPDATE admin_role_bindings
				SET status = 'revoked',
				    version = :newVersion,
				    updated_at = :updatedAt,
				    revoked_by_user_id = :revokedByUserId,
				    revoked_at = :revokedAt
				WHERE binding_id = :bindingId
				  AND status = 'active'
				  AND version = :expectedVersion
				  AND updated_at = :expectedUpdatedAt
				""")
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("revokedByUserId", changed.revokedByUserId().value())
			.param("revokedAt", databaseValue(changed.revokedAt()))
			.param("bindingId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedUpdatedAt", databaseValue(current.updatedAt()))
			.update();
		if (affected == 0) {
			throw new AdminRoleBindingConcurrentUpdateException(current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Revoking an admin role binding affected an unexpected number of rows: "
					+ affected);
		}
		return changed;
	}

	private static AdminRole mapRole(ResultSet resultSet, int rowNumber) throws SQLException {
		return new AdminRole(AdminRoleCode.from(resultSet.getString("role_code")), resultSet.getString("name"),
				resultSet.getString("description"), roleStatus(resultSet.getString("status")),
				resultSet.getBoolean("protected_role"), resultSet.getLong("version"),
				instant(resultSet, "created_at"), instant(resultSet, "updated_at"));
	}

	private static AdminRoleBinding mapBinding(ResultSet resultSet, int rowNumber) throws SQLException {
		return new AdminRoleBinding(new AdminRoleBindingId(resultSet.getObject("binding_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)),
				AdminRoleCode.from(resultSet.getString("role_code")), bindingType(resultSet.getString("binding_type")),
				bindingStatus(resultSet.getString("status")), userId(resultSet, "created_by_user_id"),
				resultSet.getString("reason"), nullableInstant(resultSet, "expires_at"), resultSet.getLong("version"),
				instant(resultSet, "created_at"), instant(resultSet, "updated_at"),
				userId(resultSet, "revoked_by_user_id"), nullableInstant(resultSet, "revoked_at"));
	}

	private static AdminRoleStatus roleStatus(String value) {
		return switch (value) {
			case "active" -> AdminRoleStatus.ACTIVE;
			case "disabled" -> AdminRoleStatus.DISABLED;
			default -> throw new IllegalStateException("Unsupported admin role status in the database: " + value);
		};
	}

	private static AdminRoleBindingType bindingType(String value) {
		return switch (value) {
			case "permanent" -> AdminRoleBindingType.PERMANENT;
			case "jit" -> AdminRoleBindingType.JIT;
			default -> throw new IllegalStateException("Unsupported admin role binding type in the database: " + value);
		};
	}

	private static AdminRoleBindingStatus bindingStatus(String value) {
		return switch (value) {
			case "active" -> AdminRoleBindingStatus.ACTIVE;
			case "revoked" -> AdminRoleBindingStatus.REVOKED;
			default -> throw new IllegalStateException("Unsupported admin role binding status in the database: " + value);
		};
	}

	private static String databaseValue(AdminRoleBindingType type) {
		return switch (type) {
			case PERMANENT -> "permanent";
			case JIT -> "jit";
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static UUID value(UserId userId) {
		return userId == null ? null : userId.value();
	}

	private static Instant instant(ResultSet resultSet, String column) throws SQLException {
		return resultSet.getObject(column, OffsetDateTime.class).toInstant();
	}

	private static Instant nullableInstant(ResultSet resultSet, String column) throws SQLException {
		OffsetDateTime value = resultSet.getObject(column, OffsetDateTime.class);
		return value == null ? null : value.toInstant();
	}

	private static UserId userId(ResultSet resultSet, String column) throws SQLException {
		UUID value = resultSet.getObject(column, UUID.class);
		return value == null ? null : new UserId(value);
	}

	private static void requireKey(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Admin role binding write requires an existing read-write transaction");
		}
	}

}
