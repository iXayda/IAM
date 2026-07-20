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

class RecoveryCodeSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019f5aff-f979-7653-8001-67ea4274f701");

	private static final UUID USER_ID =
			UUID.fromString("019f5aff-f979-7653-8001-67ea4274f702");

	private static final UUID UNKNOWN_USER_ID =
			UUID.fromString("019f5aff-f979-7653-8001-67ea4274f703");

	private static final OffsetDateTime CREATED_AT =
			OffsetDateTime.of(2026, 7, 20, 0, 0, 0, 0, ZoneOffset.UTC);

	private static final String ENCODED_CODE =
			"{pbkdf2@SpringSecurity_v5_8}0123456789abcdef0123456789abcdef";

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_recovery_codes WHERE user_id = :userId")
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
	void isolatesSelectorsPerTenantUserAndTracksConsumption() {
		insertUser(DEFAULT_TENANT_ID, USER_ID);
		insertCode(DEFAULT_TENANT_ID, USER_ID, "012AB", ENCODED_CODE, null);

		assertThatThrownBy(() -> insertCode(DEFAULT_TENANT_ID, USER_ID, "012AB", ENCODED_CODE, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		insertCode(DEFAULT_TENANT_ID, USER_ID, "CDEFG", ENCODED_CODE, CREATED_AT.plusSeconds(1));

		assertThat(this.jdbcClient.sql("""
				SELECT count(*) FROM user_recovery_codes
				WHERE tenant_id = :tenantId AND user_id = :userId AND consumed_at IS NULL
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("userId", USER_ID)
			.query(Integer.class)
			.single()).isOne();
	}

	@Test
	void enforcesUserOwnershipAndSafeStoredValues() {
		insertTenant();
		insertUser(DEFAULT_TENANT_ID, USER_ID);

		assertThatThrownBy(() -> insertCode(SECOND_TENANT_ID, USER_ID, "012AB", ENCODED_CODE, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertCode(DEFAULT_TENANT_ID, UNKNOWN_USER_ID, "012AB", ENCODED_CODE, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertCode(DEFAULT_TENANT_ID, USER_ID, "OILU1", ENCODED_CODE, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertCode(DEFAULT_TENANT_ID, USER_ID, "012AB",
				"{noop}plaintext-recovery-code-must-not-be-stored", null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertCode(DEFAULT_TENANT_ID, USER_ID, "012AB", ENCODED_CODE,
				CREATED_AT.minusSeconds(1))).isInstanceOf(DataIntegrityViolationException.class);

		assertThat(countCodes()).isZero();
	}

	@Test
	void preventsHardDeletionWhileRecoveryCodesExist() {
		insertUser(DEFAULT_TENANT_ID, USER_ID);
		insertCode(DEFAULT_TENANT_ID, USER_ID, "012AB", ENCODED_CODE, null);

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'recovery-code-schema', 'Recovery Code Schema')
				""")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	private void insertUser(UUID tenantId, UUID userId) {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.update();
	}

	private void insertCode(UUID tenantId, UUID userId, String selector, String encodedCode,
			OffsetDateTime consumedAt) {
		this.jdbcClient.sql("""
				INSERT INTO user_recovery_codes
				    (tenant_id, user_id, code_selector, encoded_code, created_at, consumed_at)
				VALUES
				    (:tenantId, :userId, :selector, :encodedCode, :createdAt, :consumedAt)
				""")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.param("selector", selector)
			.param("encodedCode", encodedCode)
			.param("createdAt", CREATED_AT)
			.param("consumedAt", consumedAt)
			.update();
	}

	private int countCodes() {
		return this.jdbcClient.sql("SELECT count(*) FROM user_recovery_codes WHERE user_id = :userId")
			.param("userId", USER_ID)
			.query(Integer.class)
			.single();
	}

}
