package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Pending recovery mutations run under the owning user's lock. */
@Repository
public class IdentityTotpRecoveryRepository {

	private final JdbcClient jdbc;

	IdentityTotpRecoveryRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Instant issue(UUID userId, UUID recoveryId, UUID oldFactorId, UUID newFactorId, UUID recoveryGenerationId, long version,
			String digest, String ciphertext, String keyId) {
		requireOne(this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				INSERT INTO iam_totp_recovery (user_id, recovery_id, old_factor_id, new_factor_id, credential_version,
				    recovery_generation_id, token_digest, secret_ciphertext, key_id, issued_at, expires_at)
				SELECT :userId, :recoveryId, :oldFactorId, :newFactorId, :version, :generationId, :digest, :secret, :keyId, now, now + INTERVAL '10 minutes'
				FROM instant ON CONFLICT (user_id) DO UPDATE SET recovery_id = EXCLUDED.recovery_id,
				    old_factor_id = EXCLUDED.old_factor_id, new_factor_id = EXCLUDED.new_factor_id,
				    credential_version = EXCLUDED.credential_version, token_digest = EXCLUDED.token_digest,
				    recovery_generation_id = EXCLUDED.recovery_generation_id,
				    secret_ciphertext = EXCLUDED.secret_ciphertext, key_id = EXCLUDED.key_id,
				    issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at
				""").param("userId", userId).param("recoveryId", recoveryId).param("oldFactorId", oldFactorId)
				.param("newFactorId", newFactorId).param("generationId", recoveryGenerationId).param("version", version).param("digest", digest)
				.param("secret", ciphertext).param("keyId", keyId).update());
		var stored = find(userId).orElseThrow(() -> new IllegalStateException("TOTP recovery was not stored"));
		if (!stored.recoveryId().equals(recoveryId) || !stored.oldFactorId().equals(oldFactorId)
				|| !stored.newFactorId().equals(newFactorId) || stored.credentialVersion() != version
				|| !stored.recoveryGenerationId().equals(recoveryGenerationId) || !stored.recoveryCodesCurrent()
				|| !stored.tokenDigest().equals(digest) || !stored.ciphertext().equals(ciphertext) || !stored.keyId().equals(keyId)) {
			throw new IllegalStateException("TOTP recovery was not stored");
		}
		return stored.expiresAt();
	}

	public Optional<Recovery> find(UUID userId) {
		return this.jdbc.sql("""
				SELECT r.*, clock_timestamp() AS now, EXISTS (SELECT 1 FROM iam_mfa_recovery_code c
				    WHERE c.user_id = r.user_id AND c.factor_id = r.old_factor_id
				    AND c.generation_id = r.recovery_generation_id AND c.consumed_at IS NOT NULL) AS codes_current
				FROM iam_totp_recovery r WHERE r.user_id = :userId
				""")
				.param("userId", userId).query((row, index) -> new Recovery(row.getObject("recovery_id", UUID.class),
						row.getObject("old_factor_id", UUID.class), row.getObject("new_factor_id", UUID.class),
						row.getObject("recovery_generation_id", UUID.class), row.getBoolean("codes_current"), row.getLong("credential_version"),
						row.getString("token_digest"), row.getString("secret_ciphertext"), row.getString("key_id"),
						row.getObject("issued_at", OffsetDateTime.class).toInstant(), row.getObject("expires_at", OffsetDateTime.class).toInstant(),
						row.getObject("now", OffsetDateTime.class).toInstant())).optional();
	}

	/** Recheck the deadline and OTP window at the consuming write, after all verification work. */
	public Optional<Instant> consume(UUID userId, UUID recoveryId, String digest, long step) {
		var consumedAt = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				DELETE FROM iam_totp_recovery USING instant WHERE user_id = :userId AND recovery_id = :recoveryId
				    AND token_digest = :digest AND expires_at > now
				    AND :step BETWEEN floor(extract(epoch FROM now) / 30)::BIGINT - 1
				        AND floor(extract(epoch FROM now) / 30)::BIGINT + 1
				RETURNING now
				""").param("userId", userId).param("recoveryId", recoveryId).param("digest", digest).param("step", step)
				.query((row, index) -> row.getObject("now", OffsetDateTime.class).toInstant()).optional();
		var remaining = find(userId);
		if (consumedAt.isPresent() && remaining.isPresent()) { throw new IllegalStateException("TOTP recovery was not consumed"); }
		if (consumedAt.isEmpty() && remaining.filter(value -> value.recoveryId().equals(recoveryId)
				&& value.tokenDigest().equals(digest) && value.expiresAt().isAfter(value.now())
				&& Math.abs(Math.floorDiv(value.now().getEpochSecond(), 30) - step) <= 1).isPresent()) {
			throw new IllegalStateException("TOTP recovery consumption was suppressed");
		}
		return consumedAt;
	}

	public void cleanUpExpired() {
		this.jdbc.sql("""
				WITH expired AS (SELECT user_id FROM iam_totp_recovery WHERE expires_at <= clock_timestamp()
				    ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
				DELETE FROM iam_totp_recovery current USING expired WHERE current.user_id = expired.user_id
				""").update();
	}

	private static void requireOne(int changed) {
		if (changed != 1) { throw new IllegalStateException("TOTP recovery mutation was not stored"); }
	}

	public record Recovery(UUID recoveryId, UUID oldFactorId, UUID newFactorId, UUID recoveryGenerationId, boolean recoveryCodesCurrent, long credentialVersion,
			String tokenDigest, String ciphertext, String keyId, Instant issuedAt, Instant expiresAt, Instant now) {

		@Override
		public String toString() {
			return "Recovery[recoveryId=" + this.recoveryId + ", secrets=REDACTED]";
		}
	}

}
