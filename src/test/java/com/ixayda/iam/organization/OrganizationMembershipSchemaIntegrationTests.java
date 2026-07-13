package com.ixayda.iam.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class OrganizationMembershipSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d41");

	private static final UUID FIRST_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d42");

	private static final UUID SECOND_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d43");

	private static final UUID UNKNOWN_ORGANIZATION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d44");

	private static final UUID FIRST_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d45");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d46");

	private static final UUID UNKNOWN_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d47");

	private static final OffsetDateTime CREATED_AT =
			OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM organization_memberships
				WHERE organization_id IN (:firstOrganizationId, :secondOrganizationId)
				   OR user_id IN (:firstUserId, :secondUserId)
				""")
			.param("firstOrganizationId", FIRST_ORGANIZATION_ID)
			.param("secondOrganizationId", SECOND_ORGANIZATION_ID)
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("""
				DELETE FROM organizations
				WHERE organization_id IN (:firstOrganizationId, :secondOrganizationId)
				""")
			.param("firstOrganizationId", FIRST_ORGANIZATION_ID)
			.param("secondOrganizationId", SECOND_ORGANIZATION_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesOneTenantScopedMembershipWithLifecycleDefaults() {
		insertOrganization(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, "membership-schema");
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);

		insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, FIRST_USER_ID);

		assertThat(this.jdbcClient.sql("""
				SELECT status = 'active'
				   AND version = 0
				   AND created_at = updated_at
				FROM organization_memberships
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND user_id = :userId
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("organizationId", FIRST_ORGANIZATION_ID)
			.param("userId", FIRST_USER_ID)
			.query(Boolean.class)
			.single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT indexdef
				FROM pg_indexes
				WHERE schemaname = current_schema()
				  AND tablename = 'organization_memberships'
				""").query(String.class).list())
			.anyMatch(definition -> definition.contains("(tenant_id, organization_id, user_id)"))
			.anyMatch(definition -> definition.contains("(tenant_id, user_id, status, organization_id)"));
	}

	@Test
	void enforcesOrganizationAndUserOwnershipWithinTheSameTenant() {
		insertTenant();
		insertOrganization(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, "default-membership");
		insertOrganization(SECOND_TENANT_ID, SECOND_ORGANIZATION_ID, "second-membership");
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);

		assertThatThrownBy(() -> insertMembership(SECOND_TENANT_ID, FIRST_ORGANIZATION_ID, SECOND_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertMembership(SECOND_TENANT_ID, SECOND_ORGANIZATION_ID, FIRST_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertMembership(DEFAULT_TENANT_ID, UNKNOWN_ORGANIZATION_ID, FIRST_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, UNKNOWN_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);

		insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, FIRST_USER_ID);
		assertThatThrownBy(() -> insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, FIRST_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(membershipCount()).isOne();
	}

	@Test
	void rejectsInvalidMembershipLifecycleMetadata() {
		insertOrganization(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, "membership-metadata");
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);

		assertRejected("invalid", 0, CREATED_AT, CREATED_AT);
		assertRejected("active", -1, CREATED_AT, CREATED_AT);
		assertRejected("removed", 1, CREATED_AT, CREATED_AT.minusSeconds(1));
		assertThat(membershipCount()).isZero();

		insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, FIRST_USER_ID, "removed", 1,
				CREATED_AT, CREATED_AT.plusSeconds(1));
		assertThat(membershipCount()).isOne();
	}

	@Test
	void preventsHardDeletionWhileARemovedMembershipExists() {
		insertOrganization(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, "membership-retention");
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);
		insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, FIRST_USER_ID, "removed", 1,
				CREATED_AT, CREATED_AT.plusSeconds(1));

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", FIRST_USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				DELETE FROM organizations
				WHERE organization_id = :organizationId
				""")
			.param("organizationId", FIRST_ORGANIZATION_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(membershipCount()).isOne();
	}

	private void assertRejected(String status, long version, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
		assertThatThrownBy(() -> insertMembership(DEFAULT_TENANT_ID, FIRST_ORGANIZATION_ID, FIRST_USER_ID,
				status, version, createdAt, updatedAt)).isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'membership-schema', 'Membership Schema')
				""")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	private void insertOrganization(UUID tenantId, UUID organizationId, String slug) {
		this.jdbcClient.sql("""
				INSERT INTO organizations (tenant_id, organization_id, slug, display_name)
				VALUES (:tenantId, :organizationId, :slug, 'Membership Organization')
				""")
			.param("tenantId", tenantId)
			.param("organizationId", organizationId)
			.param("slug", slug)
			.update();
	}

	private void insertUser(UUID tenantId, UUID userId) {
		this.jdbcClient.sql("""
				INSERT INTO users (tenant_id, user_id)
				VALUES (:tenantId, :userId)
				""")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.update();
	}

	private void insertMembership(UUID tenantId, UUID organizationId, UUID userId) {
		this.jdbcClient.sql("""
				INSERT INTO organization_memberships (tenant_id, organization_id, user_id)
				VALUES (:tenantId, :organizationId, :userId)
				""")
			.param("tenantId", tenantId)
			.param("organizationId", organizationId)
			.param("userId", userId)
			.update();
	}

	private void insertMembership(UUID tenantId, UUID organizationId, UUID userId, String status, long version,
			OffsetDateTime createdAt, OffsetDateTime updatedAt) {
		this.jdbcClient.sql("""
				INSERT INTO organization_memberships
				    (tenant_id, organization_id, user_id, status, version, created_at, updated_at)
				VALUES
				    (:tenantId, :organizationId, :userId, :status, :version, :createdAt, :updatedAt)
				""")
			.param("tenantId", tenantId)
			.param("organizationId", organizationId)
			.param("userId", userId)
			.param("status", status)
			.param("version", version)
			.param("createdAt", createdAt)
			.param("updatedAt", updatedAt)
			.update();
	}

	private int membershipCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM organization_memberships
				WHERE organization_id IN (:firstOrganizationId, :secondOrganizationId)
				   OR user_id IN (:firstUserId, :secondUserId)
				""")
			.param("firstOrganizationId", FIRST_ORGANIZATION_ID)
			.param("secondOrganizationId", SECOND_ORGANIZATION_ID)
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.query(Integer.class)
			.single();
	}

}
