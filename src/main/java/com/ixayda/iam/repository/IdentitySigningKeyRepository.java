package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Lifecycle lock serializes initialization; public reads never select encrypted private material. */
@Repository
public class IdentitySigningKeyRepository {

	private final JdbcClient jdbc;

	IdentitySigningKeyRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Lifecycle lockLifecycle() {
		return this.jdbc.sql("SELECT initial_key_id, initialized_at FROM iam_signing_key_state WHERE singleton = 1 FOR UPDATE")
				.query((row, index) -> {
					var initializedAt = row.getObject("initialized_at", OffsetDateTime.class);
					return new Lifecycle(row.getObject("initial_key_id", UUID.class), initializedAt == null ? null : initializedAt.toInstant());
				}).single();
	}

	public Optional<PublicKey> findPublicKey() {
		return this.jdbc.sql("SELECT id, algorithm, public_key, created_at FROM iam_signing_key")
				.query((row, index) -> new PublicKey(row.getObject("id", UUID.class), row.getString("algorithm"),
						row.getBytes("public_key"), row.getObject("created_at", OffsetDateTime.class).toInstant())).optional();
	}

	public Optional<StoredKey> findStoredKey() {
		return this.jdbc.sql("SELECT id, algorithm, public_key, encrypted_private_key, protection_key_id, created_at FROM iam_signing_key")
				.query(IdentitySigningKeyRepository::mapStoredKey).optional();
	}

	public void insert(UUID id, byte[] publicKey, byte[] encryptedPrivateKey, String protectionKeyId) {
		int inserted = this.jdbc.sql("""
				INSERT INTO iam_signing_key (id, algorithm, public_key, encrypted_private_key, protection_key_id)
				VALUES (:id, 'RS256', :publicKey, :encrypted, :protectionKeyId)
				""").param("id", id).param("publicKey", publicKey).param("encrypted", encryptedPrivateKey)
				.param("protectionKeyId", protectionKeyId).update();
		var stored = findStoredKey().orElseThrow(() -> new IllegalStateException("Signing key was not stored"));
		if (inserted != 1 || !id.equals(stored.id()) || !"RS256".equals(stored.algorithm())
				|| !Arrays.equals(publicKey, stored.publicKey()) || !Arrays.equals(encryptedPrivateKey, stored.encryptedPrivateKey())
				|| !protectionKeyId.equals(stored.protectionKeyId())) {
			throw new IllegalStateException("Signing key was not stored");
		}
	}

	public void completeInitialization(UUID id) {
		int changed = this.jdbc.sql("""
				UPDATE iam_signing_key_state SET initial_key_id = :id,
				    initialized_at = (SELECT created_at FROM iam_signing_key WHERE id = :id)
				WHERE singleton = 1 AND initial_key_id IS NULL
				""").param("id", id).update();
		if (changed != 1 || !id.equals(lockLifecycle().initialKeyId())) {
			throw new IllegalStateException("Signing key initialization was not stored");
		}
	}

	private static StoredKey mapStoredKey(ResultSet row, int index) throws SQLException {
		return new StoredKey(row.getObject("id", UUID.class), row.getString("algorithm"), row.getBytes("public_key"),
				row.getBytes("encrypted_private_key"), row.getString("protection_key_id"), row.getObject("created_at", OffsetDateTime.class).toInstant());
	}

	public record Lifecycle(UUID initialKeyId, Instant initializedAt) { }
	public record PublicKey(UUID id, String algorithm, byte[] publicKey, Instant createdAt) { }

	public record StoredKey(UUID id, String algorithm, byte[] publicKey, byte[] encryptedPrivateKey, String protectionKeyId, Instant createdAt) {
		@Override
		public String toString() { return "StoredKey[id=" + this.id + ", privateMaterial=REDACTED]"; }
	}

}
