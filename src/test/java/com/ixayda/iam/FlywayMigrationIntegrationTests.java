package com.ixayda.iam;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class FlywayMigrationIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID TEST_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc1");

	private static final UUID FIRST_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc2");

	private static final UUID SECOND_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc3");

	private static final UUID THIRD_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc4");

	@Autowired
	private Flyway flyway;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteOrganizationFixtures() {
		this.jdbcClient
			.sql("DELETE FROM organizations WHERE organization_id IN (:firstId, :secondId, :thirdId)")
			.param("firstId", FIRST_ORGANIZATION_ID)
			.param("secondId", SECOND_ORGANIZATION_ID)
			.param("thirdId", THIRD_ORGANIZATION_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", TEST_TENANT_ID)
			.update();
	}

	@Test
	void createsTheBuiltInTenant() {
		assertThat(count("SELECT count(*) FROM flyway_schema_history WHERE success")).isEqualTo(2);
		assertThat(count("SELECT count(*) FROM tenants")).isOne();
		assertThat(this.jdbcClient.sql("SELECT status FROM tenants WHERE slug = 'default'")
			.query(String.class)
			.single()).isEqualTo("active");
	}

	@Test
	void scopesOrganizationSlugsToATenant() {
		insertOrganization(FIRST_ORGANIZATION_ID, DEFAULT_TENANT_ID, "engineering", "Engineering");
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'second', 'Second')
				""").param("tenantId", TEST_TENANT_ID).update();
		insertOrganization(SECOND_ORGANIZATION_ID, TEST_TENANT_ID, "engineering", "Engineering");

		assertThat(count("SELECT count(*) FROM organizations WHERE slug = 'engineering'")).isEqualTo(2);
		assertThatThrownBy(() -> insertOrganization(THIRD_ORGANIZATION_ID, DEFAULT_TENANT_ID, "engineering",
				"Duplicate")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", TEST_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void protectsOrganizationInvariants() {
		assertThatThrownBy(() -> insertOrganization(FIRST_ORGANIZATION_ID, TEST_TENANT_ID, "orphan", "Orphan"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertOrganization(FIRST_ORGANIZATION_ID, DEFAULT_TENANT_ID, "Invalid Slug",
				"Invalid")).isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void protectsTenantInvariants() {
		assertThatThrownBy(() -> this.jdbcClient.sql("UPDATE tenants SET status = 'disabled' WHERE slug = 'default'")
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES ('00000000-0000-0000-0000-000000000002', 'Invalid Slug', 'Invalid')
				""").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(this.jdbcClient.sql("SELECT status FROM tenants WHERE slug = 'default'")
			.query(String.class)
			.single()).isEqualTo("active");
	}

	@Test
	void aSecondMigrationIsANoOp() {
		assertThat(this.flyway.migrate().migrationsExecuted).isZero();
	}

	private int count(String sql) {
		return this.jdbcClient.sql(sql).query(Integer.class).single();
	}

	private void insertOrganization(UUID organizationId, UUID tenantId, String slug, String displayName) {
		this.jdbcClient.sql("""
				INSERT INTO organizations (organization_id, tenant_id, slug, display_name)
				VALUES (:organizationId, :tenantId, :slug, :displayName)
				""")
			.param("organizationId", organizationId)
			.param("tenantId", tenantId)
			.param("slug", slug)
			.param("displayName", displayName)
			.update();
	}

}
