package com.ixayda.iam.group;

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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class GroupSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID FIRST_GROUP_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f111");

	private static final UUID SECOND_GROUP_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f112");

	private static final UUID SECOND_TENANT_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f113");

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createSecondTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'group-schema', 'Group Schema')
				""").param("tenantId", SECOND_TENANT_ID).update();
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM groups WHERE group_id IN (:firstId, :secondId)")
			.param("firstId", FIRST_GROUP_ID)
			.param("secondId", SECOND_GROUP_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesTenantScopedGroupsWithLifecycleDefaults() {
		insert(FIRST_GROUP_ID, TenantId.DEFAULT.value(), "\u5e73\u53f0\u7ba1\u7406\u5458");
		insert(SECOND_GROUP_ID, TenantId.DEFAULT.value(), "\u5e73\u53f0\u7ba1\u7406\u5458");

		assertThat(this.jdbcClient.sql("""
				SELECT count(*) = 2
				   AND bool_and(status = 'active')
				   AND bool_and(version = 0)
				   AND bool_and(created_at = updated_at)
				FROM groups
				WHERE tenant_id = :tenantId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.query(Boolean.class)
			.single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT indexdef FROM pg_indexes
				WHERE schemaname = current_schema() AND indexname = 'groups_active_tenant_id_idx'
				""").query(String.class).single())
			.contains("(tenant_id, group_id)", "WHERE (status = 'active'::text)");
	}

	@Test
	void enforcesTenantOwnershipAndStableIdentity() {
		insert(FIRST_GROUP_ID, SECOND_TENANT_ID, "Engineering");

		assertThatThrownBy(() -> insert(FIRST_GROUP_ID, TenantId.DEFAULT.value(), "Duplicate ID"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insert(SECOND_GROUP_ID, UUID.randomUUID(), "Unknown Tenant"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", " ", " Engineering", "Engineering ", "\u2003Engineering", "Engineering\n",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					+ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })
	void rejectsInvalidDisplayNames(String displayName) {
		assertThatThrownBy(() -> insert(FIRST_GROUP_ID, TenantId.DEFAULT.value(), displayName))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void rejectsInvalidLifecycleMetadata() {
		assertThatThrownBy(() -> insertLifecycle("invalid", 0, OffsetDateTime.now(ZoneOffset.UTC),
				OffsetDateTime.now(ZoneOffset.UTC))).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertLifecycle("active", -1, OffsetDateTime.now(ZoneOffset.UTC),
				OffsetDateTime.now(ZoneOffset.UTC))).isInstanceOf(DataIntegrityViolationException.class);
		OffsetDateTime createdAt = OffsetDateTime.now(ZoneOffset.UTC);
		assertThatThrownBy(() -> insertLifecycle("active", 0, createdAt, createdAt.minusSeconds(1)))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insert(UUID groupId, UUID tenantId, String displayName) {
		this.jdbcClient.sql("""
				INSERT INTO groups (group_id, tenant_id, display_name)
				VALUES (:groupId, :tenantId, :displayName)
				""")
			.param("groupId", groupId)
			.param("tenantId", tenantId)
			.param("displayName", displayName)
			.update();
	}

	private void insertLifecycle(String status, long version, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
		this.jdbcClient.sql("""
				INSERT INTO groups
				    (group_id, tenant_id, display_name, status, version, created_at, updated_at)
				VALUES
				    (:groupId, :tenantId, 'Lifecycle', :status, :version, :createdAt, :updatedAt)
				""")
			.param("groupId", FIRST_GROUP_ID)
			.param("tenantId", TenantId.DEFAULT.value())
			.param("status", status)
			.param("version", version)
			.param("createdAt", createdAt)
			.param("updatedAt", updatedAt)
			.update();
	}

}
