package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Deployment recovery mutations hold the user and administrator lifecycle locks. */
@Repository
public class IdentityAdministratorRecoveryRepository {

	private final JdbcClient jdbc;

	IdentityAdministratorRecoveryRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	/** The exceptional deployment path must not be available to a restricted service database identity. */
	public void requireDatabaseOwner() {
		boolean owner = this.jdbc.sql("SELECT current_user = pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()")
				.query(Boolean.class).single();
		if (!owner) { throw new IllegalStateException("Administrator recovery requires the database owner"); }
	}

	public void requireUnexpired(Instant expiresAt) {
		if (!this.jdbc.sql("SELECT :expiresAt > clock_timestamp()")
				.param("expiresAt", OffsetDateTime.ofInstant(expiresAt, java.time.ZoneOffset.UTC)).query(Boolean.class).single()) {
			throw new IllegalStateException("Administrator recovery expired during persistence");
		}
	}

	public Instant issue(UUID userId, UUID recoveryId, UUID oldFactorId, UUID newFactorId, long version,
			String digest, String ciphertext, String keyId, SecurityAuditContext audit) {
		requireOne(this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				INSERT INTO iam_administrator_recovery (user_id, recovery_id, old_factor_id, new_factor_id, credential_version,
				    token_digest, secret_ciphertext, key_id, actor, source, correlation_id, issued_at, expires_at)
				SELECT :userId, :recoveryId, :oldFactorId, :newFactorId, :version, :digest, :secret, :keyId, :actor, :source, :correlationId, now, now + INTERVAL '10 minutes'
				FROM instant ON CONFLICT (user_id) DO UPDATE SET recovery_id = EXCLUDED.recovery_id,
				    old_factor_id = EXCLUDED.old_factor_id, new_factor_id = EXCLUDED.new_factor_id,
				    credential_version = EXCLUDED.credential_version, token_digest = EXCLUDED.token_digest,
				    actor = EXCLUDED.actor, source = EXCLUDED.source, correlation_id = EXCLUDED.correlation_id,
				    secret_ciphertext = EXCLUDED.secret_ciphertext, key_id = EXCLUDED.key_id,
				    issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at
				""").param("userId", userId).param("recoveryId", recoveryId).param("oldFactorId", oldFactorId)
				.param("newFactorId", newFactorId).param("version", version).param("digest", digest)
				.param("secret", ciphertext).param("keyId", keyId).param("actor", audit.actor())
				.param("source", audit.source()).param("correlationId", audit.correlationId()).update());
		var stored = find(userId).orElseThrow(() -> new IllegalStateException("Administrator recovery was not stored"));
		if (!stored.recoveryId().equals(recoveryId) || !stored.oldFactorId().equals(oldFactorId)
				|| !stored.newFactorId().equals(newFactorId) || stored.credentialVersion() != version
				|| !stored.audit().equals(audit)
				|| !stored.tokenDigest().equals(digest) || !stored.ciphertext().equals(ciphertext) || !stored.keyId().equals(keyId)) {
			throw new IllegalStateException("Administrator recovery was not stored");
		}
		return stored.expiresAt();
	}

	public Optional<Recovery> find(UUID userId) {
		return this.jdbc.sql("SELECT r.*, clock_timestamp() AS now FROM iam_administrator_recovery r WHERE r.user_id = :userId")
				.param("userId", userId).query((row, index) -> new Recovery(row.getObject("recovery_id", UUID.class),
						row.getObject("old_factor_id", UUID.class), row.getObject("new_factor_id", UUID.class),
						row.getLong("credential_version"),
						new SecurityAuditContext(row.getString("actor"), row.getString("source"), row.getObject("correlation_id", UUID.class)),
						row.getString("token_digest"), row.getString("secret_ciphertext"), row.getString("key_id"),
						row.getObject("issued_at", OffsetDateTime.class).toInstant(), row.getObject("expires_at", OffsetDateTime.class).toInstant(),
						row.getObject("now", OffsetDateTime.class).toInstant())).optional();
	}

	/** Recheck the deadline and OTP window at the consuming write, after all verification work. */
	public Optional<Instant> consume(UUID userId, UUID recoveryId, String digest, long step) {
		var consumedAt = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				DELETE FROM iam_administrator_recovery USING instant WHERE user_id = :userId AND recovery_id = :recoveryId
				    AND token_digest = :digest AND expires_at > now
				    AND :step BETWEEN floor(extract(epoch FROM now) / 30)::BIGINT - 1
				        AND floor(extract(epoch FROM now) / 30)::BIGINT + 1
				RETURNING now
				""").param("userId", userId).param("recoveryId", recoveryId).param("digest", digest).param("step", step)
				.query((row, index) -> row.getObject("now", OffsetDateTime.class).toInstant()).optional();
		var remaining = find(userId);
		if (consumedAt.isPresent() && remaining.isPresent()) { throw new IllegalStateException("Administrator recovery was not consumed"); }
		if (consumedAt.isEmpty() && remaining.filter(value -> value.recoveryId().equals(recoveryId)
				&& value.tokenDigest().equals(digest) && value.expiresAt().isAfter(value.now())
				&& Math.abs(Math.floorDiv(value.now().getEpochSecond(), 30) - step) <= 1).isPresent()) {
			throw new IllegalStateException("Administrator recovery consumption was suppressed");
		}
		return consumedAt;
	}

	public void cleanUpExpired() {
		this.jdbc.sql("""
				WITH expired AS (SELECT user_id FROM iam_administrator_recovery WHERE expires_at <= clock_timestamp()
				    ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
				DELETE FROM iam_administrator_recovery current USING expired WHERE current.user_id = expired.user_id
				""").update();
	}

	private static void requireOne(int changed) {
		if (changed != 1) { throw new IllegalStateException("Administrator recovery mutation was not stored"); }
	}

	public record Recovery(UUID recoveryId, UUID oldFactorId, UUID newFactorId, long credentialVersion, SecurityAuditContext audit,
			String tokenDigest, String ciphertext, String keyId, Instant issuedAt, Instant expiresAt, Instant now) {

		@Override
		public String toString() {
			return "Recovery[recoveryId=" + this.recoveryId + ", secrets=REDACTED]";
		}
	}

}
