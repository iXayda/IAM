package com.ixayda.iam.authorization.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcAuthorizationSigningKeyRepository {

	private static final String COLUMNS = """
			signing_key_id, kid, key_type, key_use, signature_algorithm,
			public_modulus, public_exponent, status, attestation_version,
			attestation_key_id, attestation_tag, private_key_format,
			protection_version, encryption_key_id, initialization_vector,
			private_key_ciphertext, created_at, published_at, activate_after,
			activated_at, retired_at, publish_until, private_key_destroyed_at,
			version, updated_at
			""";

	private static final RowMapper<StoredAuthorizationSigningKey> ROW_MAPPER =
			JdbcAuthorizationSigningKeyRepository::mapRow;

	private final JdbcClient jdbcClient;

	JdbcAuthorizationSigningKeyRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	Optional<StoredAuthorizationSigningKey> findActive() {
		return this.jdbcClient.sql("SELECT " + COLUMNS + " FROM oauth_signing_keys WHERE status = 'active'")
			.query(ROW_MAPPER)
			.optional();
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void lockKeyRing() {
		requireWriteTransaction();
		this.jdbcClient.sql("LOCK TABLE oauth_signing_keys IN SHARE ROW EXCLUSIVE MODE").update();
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void insertActive(StoredAuthorizationSigningKey key) {
		requireWriteTransaction();
		if (key.status() != StoredAuthorizationSigningKey.Status.ACTIVE || key.privateKey() == null) {
			throw new IllegalArgumentException("Only an active signing key with private material can be inserted");
		}
		int affected = this.jdbcClient.sql("""
				INSERT INTO oauth_signing_keys
				    (signing_key_id, kid, key_type, key_use, signature_algorithm,
				     public_modulus, public_exponent, status, attestation_version,
				     attestation_key_id, attestation_tag, private_key_format,
				     protection_version, encryption_key_id, initialization_vector,
				     private_key_ciphertext, created_at, published_at, activate_after,
				     activated_at, version, updated_at)
				VALUES
				    (:signingKeyId, :kid, 'RSA', 'sig', 'RS256', :publicModulus,
				     :publicExponent, 'active', :attestationVersion, :attestationKeyId,
				     :attestationTag, 'PKCS8', 1, :encryptionKeyId,
				     :initializationVector, :ciphertext, :createdAt, :publishedAt,
				     :activateAfter, :activatedAt, :version, :updatedAt)
				""")
			.param("signingKeyId", key.signingKeyId())
			.param("kid", key.kid())
			.param("publicModulus", key.publicModulus())
			.param("publicExponent", key.publicExponent())
			.param("attestationVersion", key.attestation().version())
			.param("attestationKeyId", key.attestation().keyId())
			.param("attestationTag", key.attestation().tag())
			.param("encryptionKeyId", key.privateKey().keyId())
			.param("initializationVector", key.privateKey().initializationVector())
			.param("ciphertext", key.privateKey().ciphertext())
			.param("createdAt", databaseTime(key.createdAt()))
			.param("publishedAt", databaseTime(key.publishedAt()))
			.param("activateAfter", databaseTime(key.activateAfter()))
			.param("activatedAt", databaseTime(key.activatedAt()))
			.param("version", key.version())
			.param("updatedAt", databaseTime(key.updatedAt()))
			.update();
		if (affected != 1) {
			throw new IllegalStateException("Creating an authorization signing key affected an unexpected number of rows: "
					+ affected);
		}
	}

	private static StoredAuthorizationSigningKey mapRow(ResultSet resultSet, int rowNumber) throws SQLException {
		requireValue(resultSet, "key_type", "RSA");
		requireValue(resultSet, "key_use", "sig");
		requireValue(resultSet, "signature_algorithm", "RS256");
		String statusValue = resultSet.getString("status");
		StoredAuthorizationSigningKey.Status status;
		try {
			status = StoredAuthorizationSigningKey.Status.fromDatabase(statusValue);
		}
		catch (IllegalArgumentException exception) {
			throw new DataRetrievalFailureException(exception.getMessage(), exception);
		}
		String encryptionKeyId = resultSet.getString("encryption_key_id");
		AuthorizationSigningKeyCipher.ProtectedPrivateKey privateKey = null;
		if (encryptionKeyId != null) {
			requireValue(resultSet, "private_key_format", "PKCS8");
			if (resultSet.getInt("protection_version") != 1 || resultSet.wasNull()) {
				throw new DataRetrievalFailureException("Unsupported authorization signing-key protection version");
			}
			privateKey = new AuthorizationSigningKeyCipher.ProtectedPrivateKey(encryptionKeyId,
					resultSet.getBytes("initialization_vector"), resultSet.getBytes("private_key_ciphertext"));
		}
		AuthorizationSigningKeyAttestation.MetadataAttestation attestation =
				new AuthorizationSigningKeyAttestation.MetadataAttestation(resultSet.getInt("attestation_version"),
						resultSet.getString("attestation_key_id"), resultSet.getBytes("attestation_tag"));
		return new StoredAuthorizationSigningKey(resultSet.getObject("signing_key_id", java.util.UUID.class),
				resultSet.getString("kid"), resultSet.getBytes("public_modulus"), resultSet.getInt("public_exponent"),
				status, attestation, privateKey, instant(resultSet, "created_at"), instant(resultSet, "published_at"),
				instant(resultSet, "activate_after"), nullableInstant(resultSet, "activated_at"),
				nullableInstant(resultSet, "retired_at"), nullableInstant(resultSet, "publish_until"),
				nullableInstant(resultSet, "private_key_destroyed_at"), resultSet.getLong("version"),
				instant(resultSet, "updated_at"));
	}

	private static void requireValue(ResultSet resultSet, String column, String expected) throws SQLException {
		String actual = resultSet.getString(column);
		if (!expected.equals(actual)) {
			throw new DataRetrievalFailureException(
					"Unsupported authorization signing-key " + column + ": " + actual);
		}
	}

	private static Instant instant(ResultSet resultSet, String column) throws SQLException {
		return resultSet.getObject(column, OffsetDateTime.class).toInstant();
	}

	private static Instant nullableInstant(ResultSet resultSet, String column) throws SQLException {
		OffsetDateTime value = resultSet.getObject(column, OffsetDateTime.class);
		return value == null ? null : value.toInstant();
	}

	private static OffsetDateTime databaseTime(Instant value) {
		return value == null ? null : OffsetDateTime.ofInstant(value, ZoneOffset.UTC);
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("Authorization signing-key writes require a read-write transaction");
		}
	}

}
