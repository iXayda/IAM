package com.ixayda.iam.credential;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpCredentialSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019f5aff-f979-7653-8001-67ea4274f401");

	private static final UUID FIRST_USER_ID =
			UUID.fromString("019f5aff-f979-7653-8001-67ea4274f402");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019f5aff-f979-7653-8001-67ea4274f403");

	private static final OffsetDateTime CREATED_AT =
			OffsetDateTime.of(2026, 7, 20, 0, 0, 0, 0, ZoneOffset.UTC);

	private static final byte[] INITIALIZATION_VECTOR = bytes(12, 1);

	private static final byte[] CIPHERTEXT = bytes(36, 21);

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_totp_credentials WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void allowsOneActiveCredentialAndOnePendingReplacementPerUser() {
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		insertPending(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, INITIALIZATION_VECTOR);

		assertThatThrownBy(() -> insertPending(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID,
				bytes(12, 2))).isInstanceOf(DataIntegrityViolationException.class);
		insertActive(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, bytes(12, 3));
		assertThatThrownBy(() -> insertActive(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID,
				bytes(12, 4))).isInstanceOf(DataIntegrityViolationException.class);

		assertThat(countCredentials(FIRST_USER_ID)).isEqualTo(2);
	}

	@Test
	void bindsEncryptedSecretsToTenantUsersAndUniqueKeyIvPairs() {
		insertTenant();
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		insertUser(SECOND_USER_ID, SECOND_TENANT_ID);
		insertPending(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, INITIALIZATION_VECTOR);

		assertThatThrownBy(() -> insertPending(UUID.randomUUID(), SECOND_TENANT_ID, FIRST_USER_ID, bytes(12, 2)))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertPending(UUID.randomUUID(), SECOND_TENANT_ID, SECOND_USER_ID,
				INITIALIZATION_VECTOR)).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(countCredentials(FIRST_USER_ID)).isOne();
		assertThat(countCredentials(SECOND_USER_ID)).isZero();
	}

	@Test
	void rejectsInvalidProtectionAndLifecycleMetadata() {
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);

		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "pending", "sha1",
				6, 30, "invalid key", INITIALIZATION_VECTOR, CIPHERTEXT, null, 0, CREATED_AT, CREATED_AT,
				CREATED_AT.plusMinutes(10), null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "pending", "sha1",
				6, 30, "v1", bytes(11, 1), CIPHERTEXT, null, 0, CREATED_AT, CREATED_AT,
				CREATED_AT.plusMinutes(10), null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "pending", "sha1",
				6, 30, "v1", null, CIPHERTEXT, null, 0, CREATED_AT, CREATED_AT,
				CREATED_AT.plusMinutes(10), null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "pending", "sha1",
				6, 30, "v1", INITIALIZATION_VECTOR, null, null, 0, CREATED_AT, CREATED_AT,
				CREATED_AT.plusMinutes(10), null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "active", "sha1",
				6, 30, "v1", INITIALIZATION_VECTOR, CIPHERTEXT, null, 1, CREATED_AT,
				CREATED_AT.plusSeconds(30), null, CREATED_AT.plusSeconds(30), null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "pending", "sha256",
				6, 30, "v1", INITIALIZATION_VECTOR, CIPHERTEXT, null, 0, CREATED_AT, CREATED_AT,
				CREATED_AT.plusMinutes(10), null, null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "pending", "sha1",
				6, 30, "v1", INITIALIZATION_VECTOR, CIPHERTEXT, null, 0, CREATED_AT, CREATED_AT, null, null,
				null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "revoked", "sha1",
				6, 30, null, null, null, null, 1, CREATED_AT, CREATED_AT.plusSeconds(30), null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(countCredentials(FIRST_USER_ID)).isZero();
	}

	@Test
	void removesProtectedSecretMaterialFromRevokedHistory() {
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);

		assertThatThrownBy(() -> insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "revoked", "sha1",
				6, 30, "v1", INITIALIZATION_VECTOR, CIPHERTEXT, null, 1, CREATED_AT,
				CREATED_AT.plusSeconds(30), null, null, CREATED_AT.plusSeconds(30)))
			.isInstanceOf(DataIntegrityViolationException.class);
		insertRaw(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, "revoked", "sha1", 6, 30, null, null,
				null, null, 1, CREATED_AT, CREATED_AT.plusSeconds(30), null, null, CREATED_AT.plusSeconds(30));

		assertThat(this.jdbcClient.sql("""
				SELECT secret_encryption_key_id IS NULL
				   AND secret_initialization_vector IS NULL
				   AND secret_ciphertext IS NULL
				FROM user_totp_credentials
				WHERE user_id = :userId AND status = 'revoked'
				""")
			.param("userId", FIRST_USER_ID)
			.query(Boolean.class)
			.single()).isTrue();
	}

	@Test
	void preventsHardDeletionWhileCredentialHistoryExists() {
		insertUser(FIRST_USER_ID, DEFAULT_TENANT_ID);
		insertPending(UUID.randomUUID(), DEFAULT_TENANT_ID, FIRST_USER_ID, INITIALIZATION_VECTOR);

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", FIRST_USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'totp-schema', 'TOTP Schema')
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

	private void insertPending(UUID credentialId, UUID tenantId, UUID userId, byte[] initializationVector) {
		insertRaw(credentialId, tenantId, userId, "pending", "sha1", 6, 30, "v1", initializationVector,
				CIPHERTEXT, null, 0, CREATED_AT, CREATED_AT, CREATED_AT.plusMinutes(10), null, null);
	}

	private void insertActive(UUID credentialId, UUID tenantId, UUID userId, byte[] initializationVector) {
		insertRaw(credentialId, tenantId, userId, "active", "sha1", 6, 30, "v1", initializationVector,
				CIPHERTEXT, 100L, 1, CREATED_AT, CREATED_AT.plusSeconds(30), null,
				CREATED_AT.plusSeconds(30), null);
	}

	private void insertRaw(UUID credentialId, UUID tenantId, UUID userId, String status, String algorithm,
			int digits, int periodSeconds, String keyId, byte[] initializationVector, byte[] ciphertext,
			Long lastAcceptedTimeStep, long version, OffsetDateTime createdAt, OffsetDateTime updatedAt,
			OffsetDateTime enrollmentExpiresAt, OffsetDateTime activatedAt, OffsetDateTime revokedAt) {
		this.jdbcClient.sql("""
				INSERT INTO user_totp_credentials
				    (credential_id, tenant_id, user_id, status, algorithm, digits, period_seconds,
				     secret_encryption_key_id, secret_initialization_vector, secret_ciphertext,
				     last_accepted_time_step, version, created_at, updated_at, enrollment_expires_at,
				     activated_at, revoked_at)
				VALUES
				    (:credentialId, :tenantId, :userId, :status, :algorithm, :digits, :periodSeconds,
				     :keyId, :initializationVector, :ciphertext, :lastAcceptedTimeStep, :version,
				     :createdAt, :updatedAt, :enrollmentExpiresAt, :activatedAt, :revokedAt)
				""")
			.param("credentialId", credentialId)
			.param("tenantId", tenantId)
			.param("userId", userId)
			.param("status", status)
			.param("algorithm", algorithm)
			.param("digits", digits)
			.param("periodSeconds", periodSeconds)
			.param("keyId", keyId)
			.param("initializationVector", initializationVector)
			.param("ciphertext", ciphertext)
			.param("lastAcceptedTimeStep", lastAcceptedTimeStep)
			.param("version", version)
			.param("createdAt", createdAt)
			.param("updatedAt", updatedAt)
			.param("enrollmentExpiresAt", enrollmentExpiresAt)
			.param("activatedAt", activatedAt)
			.param("revokedAt", revokedAt)
			.update();
	}

	private int countCredentials(UUID userId) {
		return this.jdbcClient.sql("SELECT count(*) FROM user_totp_credentials WHERE user_id = :userId")
			.param("userId", userId)
			.query(Integer.class)
			.single();
	}

	private static byte[] bytes(int length, int offset) {
		byte[] bytes = new byte[length];
		for (int index = 0; index < length; index++) {
			bytes[index] = (byte) (offset + index);
		}
		return bytes;
	}

}
