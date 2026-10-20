package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentitySigningKeyMetadata;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Lifecycle lock serializes initialization and rotation; public reads never select encrypted private material. */
@Repository
public class IdentitySigningKeyRepository {

	private final JdbcClient jdbc;

	IdentitySigningKeyRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Lifecycle lockLifecycle() {
		return lockLifecycle(false);
	}

	/** Issuance may proceed concurrently; lifecycle changes require the exclusive lock above. */
	public Lifecycle lockForIssuance() {
		return lockLifecycle(true);
	}

	private Lifecycle lockLifecycle(boolean shared) {
		return this.jdbc.sql("SELECT initial_key_id, initialized_at, active_key_id, active_key_created_at, revision FROM iam_signing_key_state WHERE singleton = 1 " + (shared ? "FOR SHARE" : "FOR UPDATE"))
				.query((row, index) -> {
					var initializedAt = row.getObject("initialized_at", OffsetDateTime.class);
					var activeAt = row.getObject("active_key_created_at", OffsetDateTime.class);
					return new Lifecycle(row.getObject("initial_key_id", UUID.class), initializedAt == null ? null : initializedAt.toInstant(),
							row.getObject("active_key_id", UUID.class), activeAt == null ? null : activeAt.toInstant(), row.getLong("revision"));
				}).single();
	}

	public Optional<PublicKey> findPublicKey() {
		return this.jdbc.sql("SELECT id, algorithm, public_key, created_at FROM iam_signing_key WHERE status='active'")
				.query(IdentitySigningKeyRepository::mapPublicKey).optional();
	}

	public List<PublicKey> findVerificationKeys() {
		return this.jdbc.sql("SELECT id,algorithm,public_key,created_at FROM iam_signing_key WHERE status='active' OR (status='retired' AND verification_until > clock_timestamp()) ORDER BY created_at,id")
				.query(IdentitySigningKeyRepository::mapPublicKey).list();
	}

	public Optional<PublicKey> findVerificationKey(UUID id) {
		return this.jdbc.sql("SELECT id,algorithm,public_key,created_at FROM iam_signing_key WHERE id=:id AND (status='active' OR (status='retired' AND verification_until > clock_timestamp()))")
				.param("id", id).query(IdentitySigningKeyRepository::mapPublicKey).optional();
	}

	public boolean hasStoredKeys() { return this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_signing_key)").query(Boolean.class).single(); }

	public List<IdentitySigningKeyMetadata> metadata() {
		return this.jdbc.sql("SELECT id,algorithm,status,created_at,retired_at,verification_until FROM iam_signing_key ORDER BY created_at,id")
				.query((row, index) -> new IdentitySigningKeyMetadata(row.getObject("id", UUID.class), row.getString("algorithm"), IdentitySigningKeyMetadata.Status.valueOf(row.getString("status").toUpperCase(java.util.Locale.ROOT)),
						instant(row, "created_at"), instant(row, "retired_at"), instant(row, "verification_until"))).list();
	}

	public Optional<StoredKey> findStoredKey() {
		return this.jdbc.sql("SELECT id, algorithm, public_key, encrypted_private_key, protection_key_id, created_at FROM iam_signing_key WHERE status='active'")
				.query(IdentitySigningKeyRepository::mapStoredKey).optional();
	}

	/** Retired state is read only for exact post-write verification; it can never restore private material. */
	public IdentitySigningKeyMetadata retire(UUID id) {
		var stored = findStoredKey().filter(key -> key.id().equals(id)).orElseThrow(() -> new IllegalStateException("Current signing key changed"));
		var retired = this.jdbc.sql("SELECT clock_timestamp()").query(OffsetDateTime.class).single();
		var verificationUntil = retired.plusSeconds(330);
		int changed = this.jdbc.sql("""
				UPDATE iam_signing_key SET status='retired',encrypted_private_key=NULL,protection_key_id=NULL,
				    retired_at=:retiredAt,verification_until=:verificationUntil
				WHERE id=:id AND status='active'
				""").param("id", id).param("retiredAt", retired).param("verificationUntil", verificationUntil).update();
		if (changed != 1) { throw new IllegalStateException("Signing key retirement was not stored"); }
		return this.jdbc.sql("SELECT status,public_key,encrypted_private_key,protection_key_id,created_at,retired_at,verification_until FROM iam_signing_key WHERE id=:id")
				.param("id", id).query((row, index) -> {
					if (!"retired".equals(row.getString("status")) || row.getBytes("encrypted_private_key") != null || row.getString("protection_key_id") != null
							|| !Arrays.equals(stored.publicKey(), row.getBytes("public_key")) || !stored.createdAt().equals(instant(row, "created_at"))) {
						throw new IllegalStateException("Signing key retirement was not stored");
					}
					Instant retiredAt = instant(row, "retired_at"); Instant until = instant(row, "verification_until");
					if (!retired.toInstant().equals(retiredAt) || !verificationUntil.toInstant().equals(until)) { throw new IllegalStateException("Signing key retention was not stored"); }
					return new IdentitySigningKeyMetadata(id, stored.algorithm(), IdentitySigningKeyMetadata.Status.RETIRED, stored.createdAt(), retiredAt, until);
				}).single();
	}

	public void activate(UUID previous, UUID next, long revision) {
		int changed = this.jdbc.sql("""
				UPDATE iam_signing_key_state SET active_key_id=:next,
				    active_key_created_at=(SELECT created_at FROM iam_signing_key WHERE id=:next AND status='active'),revision=revision+1
				WHERE singleton=1 AND active_key_id=:previous AND revision=:revision
				""").param("previous", previous).param("next", next).param("revision", revision).update();
		var current = lockLifecycle();
		if (changed != 1 || !next.equals(current.activeKeyId()) || current.revision() != Math.addExact(revision, 1)) {
			throw new IllegalStateException("Signing key activation was not stored");
		}
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
				    initialized_at = (SELECT created_at FROM iam_signing_key WHERE id = :id), active_key_id=:id,
				    active_key_created_at=(SELECT created_at FROM iam_signing_key WHERE id=:id), revision=1
				WHERE singleton = 1 AND initial_key_id IS NULL
				""").param("id", id).update();
		var lifecycle = lockLifecycle();
		if (changed != 1 || !id.equals(lifecycle.initialKeyId()) || !id.equals(lifecycle.activeKeyId()) || lifecycle.revision() != 1) {
			throw new IllegalStateException("Signing key initialization was not stored");
		}
	}

	private static StoredKey mapStoredKey(ResultSet row, int index) throws SQLException {
		return new StoredKey(row.getObject("id", UUID.class), row.getString("algorithm"), row.getBytes("public_key"),
				row.getBytes("encrypted_private_key"), row.getString("protection_key_id"), row.getObject("created_at", OffsetDateTime.class).toInstant());
	}

	private static PublicKey mapPublicKey(ResultSet row, int index) throws SQLException {
		return new PublicKey(row.getObject("id", UUID.class), row.getString("algorithm"), row.getBytes("public_key"), instant(row, "created_at"));
	}

	private static Instant instant(ResultSet row, String column) throws SQLException { var value = row.getObject(column, OffsetDateTime.class); return value == null ? null : value.toInstant(); }

	public record Lifecycle(UUID initialKeyId, Instant initializedAt, UUID activeKeyId, Instant activeKeyCreatedAt, long revision) { }
	public record PublicKey(UUID id, String algorithm, byte[] publicKey, Instant createdAt) { }

	public record StoredKey(UUID id, String algorithm, byte[] publicKey, byte[] encryptedPrivateKey, String protectionKeyId, Instant createdAt) {
		@Override
		public String toString() { return "StoredKey[id=" + this.id + ", privateMaterial=REDACTED]"; }
	}

}
