package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class UserExternalIdentitySchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e71");

	private static final UUID FIRST_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e72");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e73");

	private static final UUID THIRD_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e74");

	private static final UUID UNKNOWN_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e75");

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM user_external_identities
				WHERE user_id IN (:firstUserId, :secondUserId, :thirdUserId)
				""")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.param("thirdUserId", THIRD_USER_ID)
			.update();
		this.jdbcClient.sql("""
				DELETE FROM users
				WHERE user_id IN (:firstUserId, :secondUserId, :thirdUserId)
				""")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.param("thirdUserId", THIRD_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesAnExplicitTenantScopedIdentityMapping() {
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);

		insertIdentity(DEFAULT_TENANT_ID, "corporate", "subject-a", FIRST_USER_ID);

		assertThat(this.jdbcClient.sql("""
				SELECT linked_at IS NOT NULL
				FROM user_external_identities
				WHERE tenant_id = :tenantId
				  AND provider_id = :providerId
				  AND subject_id = :subjectId
				  AND user_id = :userId
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("providerId", "corporate")
			.param("subjectId", "subject-a")
			.param("userId", FIRST_USER_ID)
			.query(Boolean.class)
			.single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT indexdef
				FROM pg_indexes
				WHERE schemaname = current_schema()
				  AND tablename = 'user_external_identities'
				""").query(String.class).list())
			.anyMatch(definition -> definition.contains("(tenant_id, provider_id, subject_id)"))
			.anyMatch(definition -> definition.contains("(tenant_id, user_id, provider_id)"));
		assertThat(this.jdbcClient.sql("""
				SELECT collation_name
				FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'user_external_identities'
				  AND column_name IN ('provider_id', 'subject_id')
				ORDER BY column_name
				""").query(String.class).list()).containsExactly("C", "C");
	}

	@Test
	void enforcesTenantOwnershipAndProviderScopedIdentityUniqueness() {
		insertTenant();
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);
		insertUser(DEFAULT_TENANT_ID, THIRD_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);

		assertThatThrownBy(
				() -> insertIdentity(SECOND_TENANT_ID, "corporate", "cross-tenant", FIRST_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(
				() -> insertIdentity(DEFAULT_TENANT_ID, "corporate", "unknown-user", UNKNOWN_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);

		insertIdentity(DEFAULT_TENANT_ID, "corporate", "subject-a", FIRST_USER_ID);
		assertThatThrownBy(() -> insertIdentity(DEFAULT_TENANT_ID, "corporate", "subject-a", THIRD_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertIdentity(DEFAULT_TENANT_ID, "corporate", "subject-b", FIRST_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);

		insertIdentity(DEFAULT_TENANT_ID, "corporate", "subject-b", THIRD_USER_ID);
		insertIdentity(DEFAULT_TENANT_ID, "partner", "subject-a", FIRST_USER_ID);
		insertIdentity(SECOND_TENANT_ID, "corporate", "subject-a", SECOND_USER_ID);
		assertThat(identityCount()).isEqualTo(4);
	}

	@Test
	void rejectsInvalidProviderAndSubjectIdentifiers() {
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);

		assertRejected("Corporate", "subject-a");
		assertRejected("corporate_ldap", "subject-a");
		assertRejected("corporate-", "subject-a");
		assertRejected("a".repeat(65), "subject-a");
		assertRejected("corporate", "");
		assertRejected("corporate", " subject-a");
		assertRejected("corporate", "subject-a ");
		assertRejected("corporate", "subject value");
		assertRejected("corporate", "subject\nvalue");
		assertRejected("corporate", "sübject");
		assertRejected("corporate", "subject-😀");
		assertRejected("corporate", "a".repeat(513));
		assertThat(identityCount()).isZero();

		insertIdentity(DEFAULT_TENANT_ID, "a".repeat(64), "a".repeat(512), FIRST_USER_ID);
		assertThat(identityCount()).isOne();
	}

	@Test
	void preventsHardDeletionWhileAnIdentityMappingExists() {
		insertUser(DEFAULT_TENANT_ID, FIRST_USER_ID);
		insertIdentity(DEFAULT_TENANT_ID, "corporate", "subject-a", FIRST_USER_ID);

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", FIRST_USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(identityCount()).isOne();
	}

	private void assertRejected(String providerId, String subjectId) {
		assertThatThrownBy(() -> insertIdentity(DEFAULT_TENANT_ID, providerId, subjectId, FIRST_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'external-identity-schema', 'External Identity Schema')
				""")
			.param("tenantId", SECOND_TENANT_ID)
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

	private void insertIdentity(UUID tenantId, String providerId, String subjectId, UUID userId) {
		this.jdbcClient.sql("""
				INSERT INTO user_external_identities (tenant_id, provider_id, subject_id, user_id)
				VALUES (:tenantId, :providerId, :subjectId, :userId)
				""")
			.param("tenantId", tenantId)
			.param("providerId", providerId)
			.param("subjectId", subjectId)
			.param("userId", userId)
			.update();
	}

	private int identityCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_external_identities
				WHERE user_id IN (:firstUserId, :secondUserId, :thirdUserId)
				""")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.param("thirdUserId", THIRD_USER_ID)
			.query(Integer.class)
			.single();
	}

}
