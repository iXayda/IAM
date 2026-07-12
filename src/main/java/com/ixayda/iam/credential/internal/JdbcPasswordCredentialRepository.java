package com.ixayda.iam.credential.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
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
class JdbcPasswordCredentialRepository {

	private static final String COLUMNS =
			"tenant_id, user_id, encoded_password, version, created_at, updated_at";

	private static final RowMapper<PasswordCredential> ROW_MAPPER =
			JdbcPasswordCredentialRepository::mapCredential;

	private final JdbcClient jdbcClient;

	JdbcPasswordCredentialRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = PasswordCredentialAlreadyExistsException.class)
	PasswordCredential insert(PasswordCredential credential) {
		Objects.requireNonNull(credential, "Password credential must not be null");
		requireWriteTransaction();
		if (credential.version() != 0 || !credential.createdAt().equals(credential.updatedAt())) {
			throw new IllegalArgumentException("New password credential must start at version zero and creation time");
		}
		int affected = this.jdbcClient.sql("""
				INSERT INTO user_password_credentials
				    (tenant_id, user_id, encoded_password, version, created_at, updated_at)
				VALUES
				    (:tenantId, :userId, :encodedPassword, :version, :createdAt, :updatedAt)
				ON CONFLICT (tenant_id, user_id) DO NOTHING
				""")
			.param("tenantId", credential.tenantId().value())
			.param("userId", credential.userId().value())
			.param("encodedPassword", credential.encodedPassword())
			.param("version", credential.version())
			.param("createdAt", databaseValue(credential.createdAt()))
			.param("updatedAt", databaseValue(credential.updatedAt()))
			.update();
		if (affected == 0) {
			throw new PasswordCredentialAlreadyExistsException(credential.tenantId(), credential.userId());
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Creating a password credential affected an unexpected number of rows: " + affected);
		}
		return credential;
	}

	Optional<PasswordCredential> findByUser(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(ROW_MAPPER)
			.optional();
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = PasswordCredentialConcurrentUpdateException.class)
	PasswordCredential update(PasswordCredential current, PasswordCredential changed) {
		Objects.requireNonNull(current, "Current password credential must not be null");
		Objects.requireNonNull(changed, "Changed password credential must not be null");
		requireWriteTransaction();
		if (!current.tenantId().equals(changed.tenantId()) || !current.userId().equals(changed.userId())
				|| !current.createdAt().equals(changed.createdAt()) || current.version() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1 || changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Password credential update must preserve ownership and creation time, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE user_password_credentials
				SET encoded_password = :encodedPassword,
				    version = :newVersion,
				    updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND user_id = :userId
				  AND version = :expectedVersion
				""")
			.param("encodedPassword", changed.encodedPassword())
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("userId", current.userId().value())
			.param("expectedVersion", current.version())
			.update();
		if (affected == 0) {
			throw new PasswordCredentialConcurrentUpdateException(current.tenantId(), current.userId(),
					current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Updating a password credential affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private static PasswordCredential mapCredential(ResultSet resultSet, int rowNumber) throws SQLException {
		return new PasswordCredential(new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)), resultSet.getString("encoded_password"),
				resultSet.getLong("version"), resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Password credential write requires an existing read-write transaction");
		}
	}

}
