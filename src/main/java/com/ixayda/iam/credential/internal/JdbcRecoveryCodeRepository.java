package com.ixayda.iam.credential.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcRecoveryCodeRepository {

	private static final String COLUMNS =
			"tenant_id, user_id, code_selector, encoded_code, created_at, consumed_at";

	private static final RowMapper<StoredRecoveryCode> ROW_MAPPER = JdbcRecoveryCodeRepository::mapCode;

	private final JdbcClient jdbcClient;

	JdbcRecoveryCodeRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void replaceAll(TenantId tenantId, UserId userId, List<StoredRecoveryCode> codes) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(codes, "Stored recovery codes must not be null");
		requireWriteTransaction();
		if (codes.size() != 10) {
			throw new IllegalArgumentException("Exactly ten recovery codes must be stored");
		}
		Set<String> selectors = new HashSet<>();
		for (StoredRecoveryCode code : codes) {
			if (!code.tenantId().equals(tenantId) || !code.userId().equals(userId) || code.consumedAt() != null
					|| !selectors.add(code.selector())) {
				throw new IllegalArgumentException("Recovery code replacement must contain unique new codes for one user");
			}
		}

		this.jdbcClient.sql("DELETE FROM user_recovery_codes WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.update();
		for (StoredRecoveryCode code : codes) {
			int affected = this.jdbcClient.sql("""
					INSERT INTO user_recovery_codes
					    (tenant_id, user_id, code_selector, encoded_code, created_at, consumed_at)
					VALUES
					    (:tenantId, :userId, :selector, :encodedCode, :createdAt, NULL)
					""")
				.param("tenantId", tenantId.value())
				.param("userId", userId.value())
				.param("selector", code.selector())
				.param("encodedCode", code.encodedCode())
				.param("createdAt", databaseValue(code.createdAt()))
				.update();
			if (affected != 1) {
				throw new IllegalStateException(
						"Creating a recovery code affected an unexpected number of rows: " + affected);
			}
		}
	}

	Optional<StoredRecoveryCode> findAvailable(TenantId tenantId, UserId userId, String selector) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(selector, "Recovery code selector must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_recovery_codes WHERE tenant_id = :tenantId AND user_id = :userId"
				+ " AND code_selector = :selector AND consumed_at IS NULL")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("selector", selector)
			.query(ROW_MAPPER)
			.optional();
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<StoredRecoveryCode> consume(StoredRecoveryCode observed, Instant consumedAt) {
		Objects.requireNonNull(observed, "Observed recovery code must not be null");
		Objects.requireNonNull(consumedAt, "Recovery code consumption time must not be null");
		requireWriteTransaction();
		StoredRecoveryCode consumed = observed.consume(consumedAt);
		return this.jdbcClient.sql("""
				UPDATE user_recovery_codes
				SET consumed_at = :consumedAt
				WHERE tenant_id = :tenantId
				  AND user_id = :userId
				  AND code_selector = :selector
				  AND encoded_code = :encodedCode
				  AND created_at = :createdAt
				  AND consumed_at IS NULL
				RETURNING %s
				""".formatted(COLUMNS))
			.param("consumedAt", databaseValue(consumed.consumedAt()))
			.param("tenantId", observed.tenantId().value())
			.param("userId", observed.userId().value())
			.param("selector", observed.selector())
			.param("encodedCode", observed.encodedCode())
			.param("createdAt", databaseValue(observed.createdAt()))
			.query(ROW_MAPPER)
			.optional();
	}

	int countAvailable(TenantId tenantId, UserId userId) {
		requireKey(tenantId, userId);
		return this.jdbcClient.sql("""
				SELECT count(*) FROM user_recovery_codes
				WHERE tenant_id = :tenantId AND user_id = :userId AND consumed_at IS NULL
				""")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(Integer.class)
			.single();
	}

	private static StoredRecoveryCode mapCode(ResultSet resultSet, int rowNumber) throws SQLException {
		OffsetDateTime consumedAt = resultSet.getObject("consumed_at", OffsetDateTime.class);
		return new StoredRecoveryCode(new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)), resultSet.getString("code_selector").trim(),
				resultSet.getString("encoded_code"), resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				consumedAt == null ? null : consumedAt.toInstant());
	}

	private static void requireKey(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Recovery code write requires an existing read-write transaction");
		}
	}

}
