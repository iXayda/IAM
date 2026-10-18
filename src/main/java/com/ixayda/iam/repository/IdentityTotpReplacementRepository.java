package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Pending replacement mutations run under the owning user's lock. */
@Repository
public class IdentityTotpReplacementRepository {

	private final JdbcClient jdbc;

	IdentityTotpReplacementRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Instant issue(UUID userId, UUID replacementId, UUID oldFactorId, UUID newFactorId, long version,
			String digest, String ciphertext, String keyId) {
		requireOne(this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				INSERT INTO iam_totp_replacement (user_id, replacement_id, old_factor_id, new_factor_id, credential_version,
				    token_digest, secret_ciphertext, key_id, issued_at, expires_at)
				SELECT :userId, :replacementId, :oldFactorId, :newFactorId, :version, :digest, :secret, :keyId, now, now + INTERVAL '10 minutes'
				FROM instant ON CONFLICT (user_id) DO UPDATE SET replacement_id = EXCLUDED.replacement_id,
				    old_factor_id = EXCLUDED.old_factor_id, new_factor_id = EXCLUDED.new_factor_id,
				    credential_version = EXCLUDED.credential_version, token_digest = EXCLUDED.token_digest,
				    secret_ciphertext = EXCLUDED.secret_ciphertext, key_id = EXCLUDED.key_id,
				    issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at
				""").param("userId", userId).param("replacementId", replacementId).param("oldFactorId", oldFactorId)
				.param("newFactorId", newFactorId).param("version", version).param("digest", digest)
				.param("secret", ciphertext).param("keyId", keyId).update());
		var stored = find(userId).orElseThrow(() -> new IllegalStateException("TOTP replacement was not stored"));
		if (!stored.replacementId().equals(replacementId) || !stored.oldFactorId().equals(oldFactorId)
				|| !stored.newFactorId().equals(newFactorId) || stored.credentialVersion() != version
				|| !stored.tokenDigest().equals(digest) || !stored.ciphertext().equals(ciphertext) || !stored.keyId().equals(keyId)) {
			throw new IllegalStateException("TOTP replacement was not stored");
		}
		return stored.expiresAt();
	}

	public Optional<Replacement> find(UUID userId) {
		return this.jdbc.sql("""
				SELECT r.*, clock_timestamp() AS now
				FROM iam_totp_replacement r WHERE r.user_id = :userId
				""")
				.param("userId", userId).query((row, index) -> new Replacement(row.getObject("replacement_id", UUID.class),
						row.getObject("old_factor_id", UUID.class), row.getObject("new_factor_id", UUID.class),
						row.getLong("credential_version"),
						row.getString("token_digest"), row.getString("secret_ciphertext"), row.getString("key_id"),
						row.getObject("issued_at", OffsetDateTime.class).toInstant(), row.getObject("expires_at", OffsetDateTime.class).toInstant(),
						row.getObject("now", OffsetDateTime.class).toInstant())).optional();
	}

	/** Recheck the deadline and OTP window at the consuming write, after all verification work. */
	public Optional<Instant> consume(UUID userId, UUID replacementId, String digest, long step) {
		var consumedAt = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				DELETE FROM iam_totp_replacement USING instant WHERE user_id = :userId AND replacement_id = :replacementId
				    AND token_digest = :digest AND expires_at > now
				    AND :step BETWEEN floor(extract(epoch FROM now) / 30)::BIGINT - 1
				        AND floor(extract(epoch FROM now) / 30)::BIGINT + 1
				RETURNING now
				""").param("userId", userId).param("replacementId", replacementId).param("digest", digest).param("step", step)
				.query((row, index) -> row.getObject("now", OffsetDateTime.class).toInstant()).optional();
		var remaining = find(userId);
		if (consumedAt.isPresent() && remaining.isPresent()) { throw new IllegalStateException("TOTP replacement was not consumed"); }
		if (consumedAt.isEmpty() && remaining.filter(value -> value.replacementId().equals(replacementId)
				&& value.tokenDigest().equals(digest) && value.expiresAt().isAfter(value.now())
				&& Math.abs(Math.floorDiv(value.now().getEpochSecond(), 30) - step) <= 1).isPresent()) {
			throw new IllegalStateException("TOTP replacement consumption was suppressed");
		}
		return consumedAt;
	}

	public void cleanUpExpired() {
		this.jdbc.sql("""
				WITH expired AS (SELECT user_id FROM iam_totp_replacement WHERE expires_at <= clock_timestamp()
				    ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
				DELETE FROM iam_totp_replacement current USING expired WHERE current.user_id = expired.user_id
				""").update();
	}

	private static void requireOne(int changed) {
		if (changed != 1) { throw new IllegalStateException("TOTP replacement mutation was not stored"); }
	}

	public record Replacement(UUID replacementId, UUID oldFactorId, UUID newFactorId, long credentialVersion,
			String tokenDigest, String ciphertext, String keyId, Instant issuedAt, Instant expiresAt, Instant now) {

		@Override
		public String toString() {
			return "Replacement[replacementId=" + this.replacementId + ", secrets=REDACTED]";
		}
	}

}
