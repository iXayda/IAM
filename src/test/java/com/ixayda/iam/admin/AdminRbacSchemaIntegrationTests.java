package com.ixayda.iam.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class AdminRbacSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID FIRST_USER_ID = UUID.fromString("019d2d7f-26da-7ff1-8d47-0909e7586a11");

	private static final UUID SECOND_USER_ID = UUID.fromString("019d2d7f-26da-7ff1-8d47-0909e7586a12");

	private static final UUID SECOND_TENANT_ID = UUID.fromString("019d2d7f-26da-7ff1-8d47-0909e7586a13");

	private static final UUID APPROVER_USER_ID = UUID.fromString("019d2d7f-26da-7ff1-8d47-0909e7586a14");

	private static final OffsetDateTime CREATED_AT =
			OffsetDateTime.of(2026, 7, 20, 0, 0, 0, 0, ZoneOffset.UTC);

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createPrincipals() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'admin-rbac-schema', 'Admin RBAC Schema')
				""").param("tenantId", SECOND_TENANT_ID).update();
		insertUser(TenantId.DEFAULT.value(), FIRST_USER_ID);
		insertUser(TenantId.DEFAULT.value(), APPROVER_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM admin_role_bindings
				WHERE user_id IN (:firstUserId, :secondUserId)
				""")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("""
				DELETE FROM users
				WHERE user_id IN (:firstUserId, :secondUserId, :approverUserId)
				""")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.param("approverUserId", APPROVER_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM admin_roles WHERE role_code = 'invalid_test_role'").update();
		this.jdbcClient.sql("DELETE FROM admin_permissions WHERE permission_code = 'invalid.test'").update();
	}

	@Test
	void seedsStableRolesPermissionsAndLeastPrivilegeMappings() {
		assertThat(count("admin_roles")).isEqualTo(5);
		assertThat(count("admin_permissions")).isEqualTo(23);
		assertThat(permissionCount("super_admin")).isEqualTo(23);
		assertThat(permissionCount("admin_manager")).isEqualTo(5);
		assertThat(permissionCount("user_manager")).isEqualTo(7);
		assertThat(permissionCount("auditor")).isEqualTo(2);
		assertThat(permissionCount("support")).isOne();
		assertThat(this.jdbcClient.sql("""
				SELECT string_agg(permission_code, ',' ORDER BY permission_code)
				FROM admin_role_permissions
				WHERE role_code = 'support'
				""").query(String.class).single()).isEqualTo("user.read");
		assertThat(this.jdbcClient.sql("SELECT bool_and(protected_role) FROM admin_roles")
			.query(Boolean.class)
			.single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT string_agg(granted_role_code, ',' ORDER BY granted_role_code)
				FROM admin_role_grant_rules
				WHERE granter_role_code = 'admin_manager'
				""").query(String.class).single()).isEqualTo("auditor,support,user_manager");
		assertThat(this.jdbcClient.sql("""
				SELECT indexdef
				FROM pg_indexes
				WHERE schemaname = current_schema()
				  AND indexname = 'admin_role_bindings_creator_idx'
				""").query(String.class).single())
			.contains("(tenant_id, created_by_user_id)", "WHERE (created_by_user_id IS NOT NULL)");
	}

	@Test
	void storesPermanentAndExpiringTenantScopedBindings() {
		insertBinding(TenantId.DEFAULT.value(), FIRST_USER_ID, "support", "permanent", null, null, null);
		insertBinding(TenantId.DEFAULT.value(), FIRST_USER_ID, "auditor", "jit", APPROVER_USER_ID,
				"Incident review", CREATED_AT.plusHours(1));

		assertThat(this.jdbcClient.sql("""
				SELECT string_agg(role_code || ':' || binding_type, ',' ORDER BY role_code)
				FROM admin_role_bindings
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", FIRST_USER_ID)
			.query(String.class)
			.single()).isEqualTo("auditor:jit,support:permanent");
	}

	@Test
	void preventsCrossTenantUnknownAndDuplicateBindings() {
		assertThatThrownBy(() -> insertBinding(SECOND_TENANT_ID, FIRST_USER_ID, "support", "permanent", null,
				null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertBinding(TenantId.DEFAULT.value(), FIRST_USER_ID, "support", "permanent",
				SECOND_USER_ID, null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertBinding(TenantId.DEFAULT.value(), FIRST_USER_ID, "missing_role",
				"permanent", null, null, null)).isInstanceOf(DataIntegrityViolationException.class);

		insertBinding(TenantId.DEFAULT.value(), FIRST_USER_ID, "support", "permanent", null, null, null);
		assertThatThrownBy(() -> insertBinding(TenantId.DEFAULT.value(), FIRST_USER_ID, "support", "permanent",
				null, null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(bindingCount()).isOne();
	}

	@Test
	void rejectsInvalidBindingLifetimesAndMetadata() {
		assertRejectedBinding(null, null, null, null);
		assertRejectedBinding("temporary", null, null, null);
		assertRejectedBinding("permanent", null, null, CREATED_AT.plusHours(1));
		assertRejectedBinding("jit", null, "Incident review", CREATED_AT.plusHours(1));
		assertRejectedBinding("jit", APPROVER_USER_ID, null, CREATED_AT.plusHours(1));
		assertRejectedBinding("jit", APPROVER_USER_ID, "Incident review", null);
		assertRejectedBinding("jit", APPROVER_USER_ID, "Incident review", CREATED_AT);
		assertRejectedBinding("jit", APPROVER_USER_ID, "Incident review", CREATED_AT.plusHours(8).plusSeconds(1));
		assertRejectedBinding("jit", APPROVER_USER_ID, " ", CREATED_AT.plusHours(1));
		assertRejectedBinding("jit", FIRST_USER_ID, "Self grant", CREATED_AT.plusHours(1), FIRST_USER_ID);
		assertThat(bindingCount()).isZero();
	}

	@Test
	void validatesRoleAndPermissionCatalogMetadata() {
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO admin_roles (role_code, name, description)
				VALUES ('Invalid Role', 'Invalid', 'Invalid role code')
				""").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO admin_permissions (permission_code, name, description)
				VALUES ('invalid', 'Invalid', 'Permission codes require a resource and action')
				""").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO admin_permissions (permission_code, name, description, status)
				VALUES ('invalid.test', 'Invalid', 'Invalid status', 'unknown')
				""").update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	private void assertRejectedBinding(String type, UUID createdByUserId, String reason, OffsetDateTime expiresAt) {
		assertRejectedBinding(type, createdByUserId, reason, expiresAt, FIRST_USER_ID);
	}

	private void assertRejectedBinding(String type, UUID createdByUserId, String reason, OffsetDateTime expiresAt,
			UUID userId) {
		assertThatThrownBy(() -> insertBinding(TenantId.DEFAULT.value(), userId, "support", type, createdByUserId,
				reason, expiresAt)).isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertUser(UUID tenantId, UUID userId) {
		this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id)
				VALUES (:userId, :tenantId)
				""")
			.param("userId", userId)
			.param("tenantId", tenantId)
			.update();
	}

	private void insertBinding(UUID tenantId, UUID userId, String roleCode, String bindingType,
			UUID createdByUserId, String reason, OffsetDateTime expiresAt) {
		this.jdbcClient.sql("""
				INSERT INTO admin_role_bindings
				    (tenant_id, user_id, role_code, binding_type, created_by_user_id,
				     reason, expires_at, created_at, updated_at)
				VALUES
				    (:tenantId, :userId, :roleCode, :bindingType, :createdByUserId,
				     :reason, :expiresAt, :createdAt, :createdAt)
				""")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.param("roleCode", roleCode)
			.param("bindingType", bindingType)
			.param("createdByUserId", createdByUserId)
			.param("reason", reason)
			.param("expiresAt", expiresAt)
			.param("createdAt", CREATED_AT)
			.update();
	}

	private int count(String table) {
		return this.jdbcClient.sql("SELECT count(*) FROM " + table).query(Integer.class).single();
	}

	private int permissionCount(String roleCode) {
		return this.jdbcClient.sql("SELECT count(*) FROM admin_role_permissions WHERE role_code = :roleCode")
			.param("roleCode", roleCode)
			.query(Integer.class)
			.single();
	}

	private int bindingCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM admin_role_bindings
				WHERE user_id IN (:firstUserId, :secondUserId)
				""")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.query(Integer.class)
			.single();
	}

}
