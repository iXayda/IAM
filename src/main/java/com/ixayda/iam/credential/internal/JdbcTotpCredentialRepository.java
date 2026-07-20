package com.ixayda.iam.credential.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.TotpAlgorithm;
import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.credential.TotpCredentialStatus;
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
class JdbcTotpCredentialRepository {

	private static final String COLUMNS = "credential_id, tenant_id, user_id, status, algorithm, digits, "
			+ "period_seconds, secret_encryption_key_id, secret_protection_version, "
			+ "secret_initialization_vector, secret_ciphertext, last_accepted_time_step, version, "
			+ "created_at, updated_at, enrollment_expires_at, activated_at, revoked_at";

	private static final RowMapper<StoredTotpCredential> ROW_MAPPER =
			JdbcTotpCredentialRepository::mapStoredCredential;

	private final JdbcClient jdbcClient;

	JdbcTotpCredentialRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = TotpCredentialAlreadyExistsException.class)
	StoredTotpCredential insert(StoredTotpCredential stored) {
		Objects.requireNonNull(stored, "Stored TOTP credential must not be null");
		requireWriteTransaction();
		TotpCredential credential = stored.credential();
		if (credential.status() != TotpCredentialStatus.PENDING || credential.version() != 0
				|| !credential.createdAt().equals(credential.updatedAt())) {
			throw new IllegalArgumentException("New TOTP credential must be pending at version zero");
		}
		TotpSecretCipher.ProtectedTotpSecret secret = stored.protectedSecret();
		int affected = this.jdbcClient.sql("""
				INSERT INTO user_totp_credentials
				    (credential_id, tenant_id, user_id, status, algorithm, digits, period_seconds,
				     secret_encryption_key_id, secret_protection_version, secret_initialization_vector,
				     secret_ciphertext, last_accepted_time_step, version, created_at, updated_at,
				     enrollment_expires_at, activated_at, revoked_at)
				VALUES
				    (:credentialId, :tenantId, :userId, 'pending', :algorithm, :digits, :periodSeconds,
				     :keyId, :protectionVersion, :initializationVector, :ciphertext, NULL, :version,
				     :createdAt, :updatedAt, :enrollmentExpiresAt, NULL, NULL)
				ON CONFLICT DO NOTHING
				""")
			.param("credentialId", credential.id().value())
			.param("tenantId", credential.tenantId().value())
			.param("userId", credential.userId().value())
			.param("algorithm", databaseValue(credential.algorithm()))
			.param("digits", credential.digits())
			.param("periodSeconds", credential.periodSeconds())
			.param("keyId", secret.keyId())
			.param("protectionVersion", secret.protectionVersion())
			.param("initializationVector", secret.initializationVector())
			.param("ciphertext", secret.ciphertext())
			.param("version", credential.version())
			.param("createdAt", databaseValue(credential.createdAt()))
			.param("updatedAt", databaseValue(credential.updatedAt()))
			.param("enrollmentExpiresAt", databaseValue(credential.enrollmentExpiresAt()))
			.update();
		if (affected == 0) {
			throw new TotpCredentialAlreadyExistsException(credential.tenantId(), credential.userId(),
					credential.id());
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Creating a TOTP credential affected an unexpected number of rows: " + affected);
		}
		return stored;
	}

	Optional<StoredTotpCredential> findById(TenantId tenantId, UserId userId, TotpCredentialId credentialId) {
		requireKey(tenantId, userId);
		Objects.requireNonNull(credentialId, "TOTP credential ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_totp_credentials WHERE tenant_id = :tenantId AND user_id = :userId"
				+ " AND credential_id = :credentialId")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("credentialId", credentialId.value())
			.query(ROW_MAPPER)
			.optional();
	}

	Optional<StoredTotpCredential> findPendingByUser(TenantId tenantId, UserId userId) {
		return findByUserAndStatus(tenantId, userId, TotpCredentialStatus.PENDING);
	}

	Optional<StoredTotpCredential> findActiveByUser(TenantId tenantId, UserId userId) {
		return findByUserAndStatus(tenantId, userId, TotpCredentialStatus.ACTIVE);
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = TotpCredentialConcurrentUpdateException.class)
	TotpCredential activate(StoredTotpCredential current, TotpCredential activated) {
		Objects.requireNonNull(current, "Current TOTP credential must not be null");
		Objects.requireNonNull(activated, "Activated TOTP credential must not be null");
		requireWriteTransaction();
		TotpCredential observed = current.credential();
		if (!sameIdentity(observed, activated) || observed.status() != TotpCredentialStatus.PENDING
				|| activated.status() != TotpCredentialStatus.ACTIVE || observed.version() == Long.MAX_VALUE
				|| activated.version() != observed.version() + 1
				|| activated.updatedAt().isBefore(observed.updatedAt())
				|| !activated.updatedAt().equals(activated.activatedAt())) {
			throw new IllegalArgumentException(
					"TOTP activation must preserve identity and advance one pending credential version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE user_totp_credentials
				SET status = 'active',
				    last_accepted_time_step = :lastAcceptedTimeStep,
				    version = :newVersion,
				    updated_at = :updatedAt,
				    enrollment_expires_at = NULL,
				    activated_at = :activatedAt
				WHERE credential_id = :credentialId
				  AND tenant_id = :tenantId
				  AND user_id = :userId
				  AND status = 'pending'
				  AND version = :expectedVersion
				  AND updated_at = :expectedUpdatedAt
				  AND enrollment_expires_at = :expectedEnrollmentExpiresAt
				  AND activated_at IS NULL
				  AND revoked_at IS NULL
				""")
			.param("lastAcceptedTimeStep", activated.lastAcceptedTimeStep())
			.param("newVersion", activated.version())
			.param("updatedAt", databaseValue(activated.updatedAt()))
			.param("activatedAt", databaseValue(activated.activatedAt()))
			.param("credentialId", observed.id().value())
			.param("tenantId", observed.tenantId().value())
			.param("userId", observed.userId().value())
			.param("expectedVersion", observed.version())
			.param("expectedUpdatedAt", databaseValue(observed.updatedAt()))
			.param("expectedEnrollmentExpiresAt", databaseValue(observed.enrollmentExpiresAt()))
			.update();
		requireSingleUpdate(affected, observed);
		return activated;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<StoredTotpCredential> acceptTimeStep(StoredTotpCredential observed, long timeStep, Instant verifiedAt) {
		Objects.requireNonNull(observed, "Observed TOTP credential must not be null");
		Objects.requireNonNull(verifiedAt, "TOTP verification time must not be null");
		requireWriteTransaction();
		TotpCredential credential = observed.credential();
		if (credential.status() != TotpCredentialStatus.ACTIVE || timeStep < 0
				|| verifiedAt.isBefore(credential.updatedAt())) {
			throw new IllegalArgumentException("Only a newer time step on an active TOTP credential can be accepted");
		}
		if (timeStep <= credential.lastAcceptedTimeStep()) {
			return Optional.empty();
		}

		return this.jdbcClient.sql("""
				UPDATE user_totp_credentials
				SET last_accepted_time_step = :timeStep,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, :verifiedAt)
				WHERE credential_id = :credentialId
				  AND tenant_id = :tenantId
				  AND user_id = :userId
				  AND status = 'active'
				  AND version < 9223372036854775807
				  AND last_accepted_time_step < :timeStep
				RETURNING %s
				""".formatted(COLUMNS))
			.param("timeStep", timeStep)
			.param("verifiedAt", databaseValue(verifiedAt))
			.param("credentialId", credential.id().value())
			.param("tenantId", credential.tenantId().value())
			.param("userId", credential.userId().value())
			.query(ROW_MAPPER)
			.optional();
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = TotpCredentialConcurrentUpdateException.class)
	TotpCredential revoke(StoredTotpCredential current, TotpCredential revoked) {
		Objects.requireNonNull(current, "Current TOTP credential must not be null");
		Objects.requireNonNull(revoked, "Revoked TOTP credential must not be null");
		requireWriteTransaction();
		TotpCredential observed = current.credential();
		if (!sameIdentity(observed, revoked) || observed.status() == TotpCredentialStatus.REVOKED
				|| revoked.status() != TotpCredentialStatus.REVOKED || observed.version() == Long.MAX_VALUE
				|| revoked.version() != observed.version() + 1 || revoked.updatedAt().isBefore(observed.updatedAt())
				|| !revoked.updatedAt().equals(revoked.revokedAt())
				|| !Objects.equals(observed.activatedAt(), revoked.activatedAt())
				|| !Objects.equals(observed.lastAcceptedTimeStep(), revoked.lastAcceptedTimeStep())) {
			throw new IllegalArgumentException(
					"TOTP revocation must preserve identity and advance one usable credential version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE user_totp_credentials
				SET status = 'revoked',
				    secret_encryption_key_id = NULL,
				    secret_initialization_vector = NULL,
				    secret_ciphertext = NULL,
				    version = :newVersion,
				    updated_at = :updatedAt,
				    enrollment_expires_at = NULL,
				    revoked_at = :revokedAt
				WHERE credential_id = :credentialId
				  AND tenant_id = :tenantId
				  AND user_id = :userId
				  AND status = :expectedStatus
				  AND version = :expectedVersion
				  AND updated_at = :expectedUpdatedAt
				  AND revoked_at IS NULL
				""")
			.param("newVersion", revoked.version())
			.param("updatedAt", databaseValue(revoked.updatedAt()))
			.param("revokedAt", databaseValue(revoked.revokedAt()))
			.param("credentialId", observed.id().value())
			.param("tenantId", observed.tenantId().value())
			.param("userId", observed.userId().value())
			.param("expectedStatus", databaseValue(observed.status()))
			.param("expectedVersion", observed.version())
			.param("expectedUpdatedAt", databaseValue(observed.updatedAt()))
			.update();
		requireSingleUpdate(affected, observed);
		return revoked;
	}

	private Optional<StoredTotpCredential> findByUserAndStatus(TenantId tenantId, UserId userId,
			TotpCredentialStatus status) {
		requireKey(tenantId, userId);
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM user_totp_credentials WHERE tenant_id = :tenantId AND user_id = :userId"
				+ " AND status = :status")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("status", databaseValue(status))
			.query(ROW_MAPPER)
			.optional();
	}

	private static StoredTotpCredential mapStoredCredential(ResultSet resultSet, int rowNumber) throws SQLException {
		TotpCredentialStatus status = status(resultSet.getString("status"));
		TotpCredential credential = new TotpCredential(
				new TotpCredentialId(resultSet.getObject("credential_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)), status,
				algorithm(resultSet.getString("algorithm")), resultSet.getInt("digits"),
				resultSet.getInt("period_seconds"), resultSet.getObject("last_accepted_time_step", Long.class),
				resultSet.getLong("version"), instant(resultSet, "created_at"), instant(resultSet, "updated_at"),
				nullableInstant(resultSet, "enrollment_expires_at"), nullableInstant(resultSet, "activated_at"),
				nullableInstant(resultSet, "revoked_at"));
		TotpSecretCipher.ProtectedTotpSecret secret = status == TotpCredentialStatus.REVOKED ? null
				: new TotpSecretCipher.ProtectedTotpSecret(resultSet.getInt("secret_protection_version"),
						resultSet.getString("secret_encryption_key_id"),
						resultSet.getBytes("secret_initialization_vector"), resultSet.getBytes("secret_ciphertext"));
		return new StoredTotpCredential(credential, secret);
	}

	private static boolean sameIdentity(TotpCredential left, TotpCredential right) {
		return left.id().equals(right.id()) && left.tenantId().equals(right.tenantId())
				&& left.userId().equals(right.userId()) && left.algorithm() == right.algorithm()
				&& left.digits() == right.digits() && left.periodSeconds() == right.periodSeconds()
				&& left.createdAt().equals(right.createdAt());
	}

	private static void requireSingleUpdate(int affected, TotpCredential observed) {
		if (affected == 0) {
			throw new TotpCredentialConcurrentUpdateException(observed.id(), observed.version());
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Updating a TOTP credential affected an unexpected number of rows: " + affected);
		}
	}

	private static void requireKey(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
	}

	private static String databaseValue(TotpAlgorithm algorithm) {
		return switch (algorithm) {
			case SHA1 -> "sha1";
		};
	}

	private static String databaseValue(TotpCredentialStatus status) {
		return switch (status) {
			case PENDING -> "pending";
			case ACTIVE -> "active";
			case REVOKED -> "revoked";
		};
	}

	private static TotpAlgorithm algorithm(String value) {
		return switch (value) {
			case "sha1" -> TotpAlgorithm.SHA1;
			default -> throw new IllegalStateException("Unsupported TOTP algorithm in the database: " + value);
		};
	}

	private static TotpCredentialStatus status(String value) {
		return switch (value) {
			case "pending" -> TotpCredentialStatus.PENDING;
			case "active" -> TotpCredentialStatus.ACTIVE;
			case "revoked" -> TotpCredentialStatus.REVOKED;
			default -> throw new IllegalStateException("Unsupported TOTP credential status in the database: " + value);
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static Instant instant(ResultSet resultSet, String column) throws SQLException {
		return resultSet.getObject(column, OffsetDateTime.class).toInstant();
	}

	private static Instant nullableInstant(ResultSet resultSet, String column) throws SQLException {
		OffsetDateTime value = resultSet.getObject(column, OffsetDateTime.class);
		return value == null ? null : value.toInstant();
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"TOTP credential write requires an existing read-write transaction");
		}
	}

}
