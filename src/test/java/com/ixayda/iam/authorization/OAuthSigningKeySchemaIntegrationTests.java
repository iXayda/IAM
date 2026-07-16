package com.ixayda.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class OAuthSigningKeySchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID FIRST_KEY_ID = UUID.fromString("019cf2eb-c956-75e2-9cf1-9042aaa91001");

	private static final UUID SECOND_KEY_ID = UUID.fromString("019cf2eb-c956-75e2-9cf1-9042aaa91002");

	private static final UUID THIRD_KEY_ID = UUID.fromString("019cf2eb-c956-75e2-9cf1-9042aaa91003");

	private static final UUID FOURTH_KEY_ID = UUID.fromString("019cf2eb-c956-75e2-9cf1-9042aaa91004");

	private static final OffsetDateTime CREATED_AT =
			OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM oauth_signing_keys
				WHERE signing_key_id IN (:first, :second, :third, :fourth)
				""")
			.param("first", FIRST_KEY_ID)
			.param("second", SECOND_KEY_ID)
			.param("third", THIRD_KEY_ID)
			.param("fourth", FOURTH_KEY_ID)
			.update();
	}

	@Test
	void storesStagedActiveAndRetiredKeyLifecycles() {
		insertStaged(FIRST_KEY_ID, (byte) 1);
		UUID activeKeyId = findActiveKeyId().orElseGet(() -> {
			insertActive(SECOND_KEY_ID, (byte) 2);
			return SECOND_KEY_ID;
		});
		insertRetired(THIRD_KEY_ID, (byte) 3);

		assertThat(status(FIRST_KEY_ID)).contains("staged");
		assertThat(status(activeKeyId)).contains("active");
		assertThat(status(THIRD_KEY_ID)).contains("retired");
		assertThat(this.jdbcClient.sql("""
				SELECT private_key_ciphertext IS NULL AND private_key_destroyed_at IS NOT NULL
				FROM oauth_signing_keys
				WHERE signing_key_id = :keyId
				""").param("keyId", THIRD_KEY_ID).query(Boolean.class).single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT collation_name
				FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'oauth_signing_keys'
				  AND column_name IN (
				      'kid', 'key_type', 'key_use', 'signature_algorithm', 'status',
				      'attestation_key_id', 'private_key_format', 'encryption_key_id')
				""").query(String.class).list()).containsOnly("C");
	}

	@Test
	void permitsOnlyOneStagedAndOneActiveKey() {
		if (findActiveKeyId().isEmpty()) {
			insertActive(FIRST_KEY_ID, (byte) 1);
		}
		assertThatThrownBy(() -> insertActive(SECOND_KEY_ID, (byte) 2))
			.isInstanceOf(DataIntegrityViolationException.class);

		insertStaged(THIRD_KEY_ID, (byte) 3);
		assertThatThrownBy(() -> insertStaged(FOURTH_KEY_ID, (byte) 4))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void rejectsInvalidIdentityMaterialAndLifecycleState() {
		insertStaged(FIRST_KEY_ID, (byte) 1);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys SET kid = 'invalid' WHERE signing_key_id = :keyId
				""").param("keyId", FIRST_KEY_ID).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys SET signature_algorithm = 'ES256' WHERE signing_key_id = :keyId
				""").param("keyId", FIRST_KEY_ID).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys SET public_exponent = 3 WHERE signing_key_id = :keyId
				""").param("keyId", FIRST_KEY_ID).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys SET private_key_format = NULL WHERE signing_key_id = :keyId
				""").param("keyId", FIRST_KEY_ID).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys SET attestation_tag = :tag WHERE signing_key_id = :keyId
				""")
			.param("tag", material(31, (byte) 1))
			.param("keyId", FIRST_KEY_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRetired(SECOND_KEY_ID, (byte) 1))
			.isInstanceOf(DataIntegrityViolationException.class);

		insertRetired(THIRD_KEY_ID, (byte) 3);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys
				SET retired_at = activated_at - interval '1 second'
				WHERE signing_key_id = :keyId
				""").param("keyId", THIRD_KEY_ID).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_signing_keys
				SET encryption_key_id = 'test-v1', initialization_vector = :iv,
				    private_key_ciphertext = :ciphertext
				WHERE signing_key_id = :keyId
				""")
			.param("iv", material(12, (byte) 4))
			.param("ciphertext", material(1024, (byte) 4))
			.param("keyId", THIRD_KEY_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertStaged(UUID keyId, byte marker) {
		insert(keyId, kid(marker), "staged", modulus(marker), "PKCS8", 1, "test-v1", material(12, marker),
				material(1024, marker), CREATED_AT, CREATED_AT, CREATED_AT.plusSeconds(60), null, null, null,
				null, CREATED_AT);
	}

	private void insertActive(UUID keyId, byte marker) {
		insert(keyId, kid(marker), "active", modulus(marker), "PKCS8", 1, "test-v1", material(12, marker),
				material(1024, marker), CREATED_AT, CREATED_AT, CREATED_AT, CREATED_AT, null, null, null,
				CREATED_AT);
	}

	private void insertRetired(UUID keyId, byte marker) {
		insert(keyId, kid(marker), "retired", modulus(marker), null, null, null, null, null, CREATED_AT,
				CREATED_AT, CREATED_AT.plusSeconds(1), CREATED_AT.plusSeconds(1), CREATED_AT.plusSeconds(2),
				CREATED_AT.plusSeconds(3600), CREATED_AT.plusSeconds(2), CREATED_AT.plusSeconds(2));
	}

	private void insert(UUID keyId, String kid, String status, byte[] modulus, String privateKeyFormat,
			Integer protectionVersion, String encryptionKeyId, byte[] initializationVector, byte[] ciphertext,
			OffsetDateTime createdAt, OffsetDateTime publishedAt, OffsetDateTime activateAfter,
			OffsetDateTime activatedAt, OffsetDateTime retiredAt, OffsetDateTime publishUntil,
			OffsetDateTime privateKeyDestroyedAt, OffsetDateTime updatedAt) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_signing_keys
				    (signing_key_id, kid, key_type, key_use, signature_algorithm,
				     public_modulus, public_exponent, status, attestation_version,
				     attestation_key_id, attestation_tag, private_key_format,
				     protection_version, encryption_key_id, initialization_vector,
				     private_key_ciphertext, created_at, published_at, activate_after,
				     activated_at, retired_at, publish_until, private_key_destroyed_at, updated_at)
				VALUES
				    (:keyId, :kid, 'RSA', 'sig', 'RS256', :modulus, 65537, :status,
				     1, 'test-v1', :attestationTag, :privateKeyFormat, :protectionVersion, :encryptionKeyId,
				     :initializationVector, :ciphertext, :createdAt, :publishedAt,
				     :activateAfter, :activatedAt, :retiredAt, :publishUntil,
				     :privateKeyDestroyedAt, :updatedAt)
				""")
			.param("keyId", keyId)
			.param("kid", kid)
			.param("modulus", modulus)
			.param("status", status)
			.param("attestationTag", material(32, modulus[1]))
			.param("privateKeyFormat", privateKeyFormat)
			.param("protectionVersion", protectionVersion)
			.param("encryptionKeyId", encryptionKeyId)
			.param("initializationVector", initializationVector)
			.param("ciphertext", ciphertext)
			.param("createdAt", createdAt)
			.param("publishedAt", publishedAt)
			.param("activateAfter", activateAfter)
			.param("activatedAt", activatedAt)
			.param("retiredAt", retiredAt)
			.param("publishUntil", publishUntil)
			.param("privateKeyDestroyedAt", privateKeyDestroyedAt)
			.param("updatedAt", updatedAt)
			.update();
	}

	private Optional<UUID> findActiveKeyId() {
		return this.jdbcClient.sql("SELECT signing_key_id FROM oauth_signing_keys WHERE status = 'active'")
			.query(UUID.class)
			.optional();
	}

	private Optional<String> status(UUID keyId) {
		return this.jdbcClient.sql("SELECT status FROM oauth_signing_keys WHERE signing_key_id = :keyId")
			.param("keyId", keyId)
			.query(String.class)
			.optional();
	}

	private static String kid(byte marker) {
		return "A".repeat(42) + Character.forDigit(marker, 10);
	}

	private static byte[] modulus(byte marker) {
		byte[] modulus = material(384, marker);
		modulus[0] = (byte) (modulus[0] | 0x80);
		modulus[modulus.length - 1] = (byte) (modulus[modulus.length - 1] | 1);
		return modulus;
	}

	private static byte[] material(int length, byte value) {
		byte[] bytes = new byte[length];
		Arrays.fill(bytes, value);
		return bytes;
	}

}
