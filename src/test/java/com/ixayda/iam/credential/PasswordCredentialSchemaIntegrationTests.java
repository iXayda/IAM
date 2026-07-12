package com.ixayda.iam.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class PasswordCredentialSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d01");

	private static final UUID USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d02");

	private static final UUID UNKNOWN_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0d03");

	private static final String ENCODED_PASSWORD =
			"{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG";

	private static final String NEXT_ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}0123456789abcdef0123456789abcdef";

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void keepsOneCurrentPasswordPerUser() {
		insertUser(USER_ID, DEFAULT_TENANT_ID);
		insertCredential(DEFAULT_TENANT_ID, USER_ID, ENCODED_PASSWORD);
		OffsetDateTime createdAt = this.jdbcClient.sql("""
				SELECT created_at FROM user_password_credentials
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("userId", USER_ID)
			.query(OffsetDateTime.class)
			.single();

		assertThatThrownBy(() -> insertCredential(DEFAULT_TENANT_ID, USER_ID, NEXT_ENCODED_PASSWORD))
			.isInstanceOf(DataIntegrityViolationException.class);

		this.jdbcClient.sql("""
				UPDATE user_password_credentials
				SET encoded_password = :encodedPassword,
				    version = version + 1,
				    updated_at = now()
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("encodedPassword", NEXT_ENCODED_PASSWORD)
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("userId", USER_ID)
			.update();

		assertThat(countCredentials(USER_ID)).isOne();
		assertThat(this.jdbcClient.sql("""
				SELECT encoded_password = :encodedPassword
				   AND version = 1
				   AND created_at = :createdAt
				   AND updated_at >= created_at
				FROM user_password_credentials
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("encodedPassword", NEXT_ENCODED_PASSWORD)
			.param("createdAt", createdAt)
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("userId", USER_ID)
			.query(Boolean.class)
			.single()).isTrue();
	}

	@Test
	void enforcesTenantScopedUserOwnership() {
		insertTenant();
		insertUser(USER_ID, DEFAULT_TENANT_ID);

		assertThatThrownBy(() -> insertCredential(SECOND_TENANT_ID, USER_ID, ENCODED_PASSWORD))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertCredential(DEFAULT_TENANT_ID, UNKNOWN_USER_ID, ENCODED_PASSWORD))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(countCredentials(USER_ID)).isZero();
	}

	@Test
	void rejectsUnsafeEncodingAndInvalidMetadata() {
		insertUser(USER_ID, DEFAULT_TENANT_ID);

		assertThatThrownBy(() -> insertCredential(DEFAULT_TENANT_ID, USER_ID,
				"$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertCredential(DEFAULT_TENANT_ID, USER_ID,
				"{noop}this-is-a-plaintext-password-and-must-not-be-stored"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO user_password_credentials
				    (tenant_id, user_id, encoded_password, version)
				VALUES
				    (:tenantId, :userId, :encodedPassword, -1)
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("userId", USER_ID)
			.param("encodedPassword", ENCODED_PASSWORD)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO user_password_credentials
				    (tenant_id, user_id, encoded_password, created_at, updated_at)
				VALUES
				    (:tenantId, :userId, :encodedPassword, now(), now() - interval '1 second')
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("userId", USER_ID)
			.param("encodedPassword", ENCODED_PASSWORD)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(countCredentials(USER_ID)).isZero();
	}

	@Test
	void preventsHardDeletionWhileAPasswordExists() {
		insertUser(USER_ID, DEFAULT_TENANT_ID);
		insertCredential(DEFAULT_TENANT_ID, USER_ID, ENCODED_PASSWORD);

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(countCredentials(USER_ID)).isOne();
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'password-schema', 'Password Schema')
				""")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
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

	private void insertCredential(UUID tenantId, UUID userId, String encodedPassword) {
		this.jdbcClient.sql("""
				INSERT INTO user_password_credentials
				    (tenant_id, user_id, encoded_password)
				VALUES
				    (:tenantId, :userId, :encodedPassword)
				""")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.param("encodedPassword", encodedPassword)
			.update();
	}

	private int countCredentials(UUID userId) {
		return this.jdbcClient.sql("SELECT count(*) FROM user_password_credentials WHERE user_id = :userId")
			.param("userId", userId)
			.query(Integer.class)
			.single();
	}

}
