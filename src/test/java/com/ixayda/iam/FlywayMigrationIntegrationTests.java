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

	private static final int CURRENT_SCHEMA_VERSION = 25;

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID TEST_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc1");

	private static final UUID UNKNOWN_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc8");

	private static final UUID FIRST_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc2");

	private static final UUID SECOND_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc3");

	private static final UUID THIRD_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc4");

	private static final UUID FIRST_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc5");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc6");

	private static final UUID THIRD_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc7");

	@Autowired
	private Flyway flyway;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient
			.sql("DELETE FROM user_external_identities WHERE user_id IN (:firstId, :secondId, :thirdId)")
			.param("firstId", FIRST_USER_ID)
			.param("secondId", SECOND_USER_ID)
			.param("thirdId", THIRD_USER_ID)
			.update();
		this.jdbcClient
			.sql("DELETE FROM user_login_identifiers WHERE user_id IN (:firstId, :secondId, :thirdId)")
			.param("firstId", FIRST_USER_ID)
			.param("secondId", SECOND_USER_ID)
			.param("thirdId", THIRD_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstId, :secondId, :thirdId)")
			.param("firstId", FIRST_USER_ID)
			.param("secondId", SECOND_USER_ID)
			.param("thirdId", THIRD_USER_ID)
			.update();
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
		assertThat(count("SELECT count(*) FROM flyway_schema_history WHERE success"))
			.isEqualTo(CURRENT_SCHEMA_VERSION);
		assertThat(count("SELECT count(*) FROM tenants")).isOne();
		assertThat(this.jdbcClient.sql("SELECT status FROM tenants WHERE slug = 'default'")
			.query(String.class)
			.single()).isEqualTo("active");
	}

	@Test
	void scopesLoginIdentifiersToATenantAndAcrossIdentifierTypes() {
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		insertTenant();
		insertUser(SECOND_USER_ID, TEST_TENANT_ID);
		insertUser(THIRD_USER_ID, DEFAULT_TENANT_ID);
		insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "username", "15551234567", "15551234567");
		insertIdentifier(SECOND_USER_ID, TEST_TENANT_ID, "phone", "+1 (555) 123-4567", "15551234567");

		assertThat(count("SELECT count(*) FROM user_login_identifiers WHERE canonical_value = '15551234567'"))
			.isEqualTo(2);
		assertThatThrownBy(() -> insertIdentifier(THIRD_USER_ID, DEFAULT_TENANT_ID, "phone", "15551234567",
				"15551234567")).isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void enforcesTenantOwnership() {
		insertTenant();
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		insertUser(SECOND_USER_ID, TEST_TENANT_ID);

		assertThatThrownBy(() -> insertUser(THIRD_USER_ID, UNKNOWN_TENANT_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, TEST_TENANT_ID, "username", "alice", "alice"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", TEST_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void protectsUserAndLoginIdentifierInvariants() {
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, status)
				VALUES (:userId, :tenantId, 'invalid')
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, version)
				VALUES (:userId, :tenantId, -1)
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, version, security_version)
				VALUES (:userId, :tenantId, 0, 1)
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, version, security_version)
				VALUES (:userId, :tenantId, 0, -1)
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, version, security_version)
				VALUES (:userId, :tenantId, 0, NULL)
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, created_at, updated_at)
				VALUES (:userId, :tenantId, now(), now() - interval '1 second')
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, created_at, last_login_at)
				VALUES (:userId, :tenantId, now(), now() - interval '1 second')
				""")
			.param("userId", FIRST_USER_ID)
			.param("tenantId", DEFAULT_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);

		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "invalid", "alice", "alice"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "email", " alice@example.com ",
				"alice@example.com")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "email", "Alice@example.com",
				"Alice@example.com")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "email", "alice@example.com",
				"bob@example.com")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "email", "alice@@example.com",
				"alice@@example.com")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "email",
				"alice\u0001@example.com", "alice\u0001@example.com"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "phone", "+15551234567",
				"+15551234567")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "phone", "+1\t5551234567",
				"15551234567")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "username", "123-456",
				"123-456")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "username", "123.456",
				"123.456")).isInstanceOf(DataIntegrityViolationException.class);
		insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "username", "123456", "123456");
	}

	@Test
	void retainsLoginIdentifiersForSoftDeletedUsers() {
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		insertIdentifier(FIRST_USER_ID, DEFAULT_TENANT_ID, "email", "alice@example.com", "alice@example.com");
		this.jdbcClient.sql("UPDATE users SET status = 'deleted' WHERE user_id = :userId")
			.param("userId", FIRST_USER_ID)
			.update();
		insertUser(SECOND_USER_ID, DEFAULT_TENANT_ID);

		assertThatThrownBy(() -> insertIdentifier(SECOND_USER_ID, DEFAULT_TENANT_ID, "email", "Alice@example.com",
				"alice@example.com")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", FIRST_USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
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

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'user-schema', 'User Schema')
				""").param("tenantId", TEST_TENANT_ID).update();
	}

	private void insertUser(UUID userId, UUID tenantId) {
		this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id)
				VALUES (:userId, :tenantId)
				""")
			.param("userId", userId)
			.param("tenantId", tenantId)
			.update();
	}

	private void insertIdentifier(UUID userId, UUID tenantId, String type, String value, String canonicalValue) {
		this.jdbcClient.sql("""
				INSERT INTO user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value)
				VALUES
				    (:tenantId, :userId, :type, :value, :canonicalValue)
				""")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.param("type", type)
			.param("value", value)
			.param("canonicalValue", canonicalValue)
			.update();
	}

}
