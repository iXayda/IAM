package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Factor operations run under the owning user's lock. */
@Repository
public class IdentityTotpRepository {

	private final JdbcClient jdbc;

	IdentityTotpRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Instant enroll(UUID userId, UUID factorId, String encryptedSecret, String keyId, long credentialVersion) {
		Instant expires = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				INSERT INTO iam_user_totp (user_id, factor_id, secret_ciphertext, key_id, enrollment_credential_version,
				    status, issued_at, expires_at)
				SELECT :userId, :factorId, :secret, :keyId, :version, 'pending', now, now + INTERVAL '10 minutes' FROM instant
				ON CONFLICT (user_id) DO UPDATE SET factor_id = EXCLUDED.factor_id, secret_ciphertext = EXCLUDED.secret_ciphertext,
				    key_id = EXCLUDED.key_id, enrollment_credential_version = EXCLUDED.enrollment_credential_version, status = 'pending',
				    issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, activated_at = NULL, last_used_step = NULL
				WHERE iam_user_totp.status = 'pending'
				RETURNING expires_at
				""").param("userId", userId).param("factorId", factorId).param("secret", encryptedSecret)
				.param("keyId", keyId).param("version", credentialVersion)
				.query((row, index) -> row.getObject("expires_at", OffsetDateTime.class).toInstant()).single();
		var stored = find(userId).orElseThrow(() -> new IllegalStateException("TOTP enrollment was not stored"));
		if (!stored.factorId().equals(factorId) || !stored.encryptedSecret().equals(encryptedSecret)
				|| !stored.keyId().equals(keyId) || stored.enrollmentCredentialVersion() != credentialVersion || stored.active()) {
			throw new IllegalStateException("TOTP enrollment was not stored");
		}
		return expires;
	}

	public Optional<Factor> find(UUID userId) {
		return this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				SELECT factor_id, secret_ciphertext, key_id, enrollment_credential_version, status, last_used_step,
				    expires_at > now AS unexpired, now
				FROM iam_user_totp CROSS JOIN instant WHERE user_id = :userId
				""").param("userId", userId).query((row, index) -> new Factor(row.getObject("factor_id", UUID.class),
						row.getString("secret_ciphertext"), row.getString("key_id"), row.getLong("enrollment_credential_version"),
						row.getString("status").equals("active"), row.getObject("last_used_step", Long.class),
						row.getBoolean("unexpired"), row.getObject("now", OffsetDateTime.class).toInstant())).optional();
	}

	public Optional<Instant> consume(UUID userId, UUID factorId, long step, boolean activate) {
		var consumedAt = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now),
				eligible AS MATERIALIZED (
				    SELECT 1 FROM iam_user_totp CROSS JOIN instant
				    WHERE user_id = :userId AND factor_id = :factorId
				        AND status = :expectedStatus AND (NOT :activate OR expires_at > now)
				        AND (last_used_step IS NULL OR last_used_step < :step)
				        AND :step BETWEEN floor(extract(epoch FROM now) / 30)::BIGINT - 1
				            AND floor(extract(epoch FROM now) / 30)::BIGINT + 1
				), consumed AS (
				UPDATE iam_user_totp SET status = 'active', last_used_step = :step,
				    activated_at = CASE WHEN :activate THEN now ELSE activated_at END
				FROM instant WHERE user_id = :userId AND factor_id = :factorId
				    AND EXISTS (SELECT 1 FROM eligible)
				RETURNING now
				)
				SELECT (SELECT now FROM consumed) AS consumed_at, EXISTS (SELECT 1 FROM eligible) AS eligible
				""").param("userId", userId).param("factorId", factorId).param("step", step)
				.param("activate", activate).param("expectedStatus", activate ? "pending" : "active")
				.query((row, index) -> {
					var time = row.getObject("consumed_at", OffsetDateTime.class);
					if (time == null && row.getBoolean("eligible")) {
						throw new IllegalStateException("TOTP consumption was not stored");
					}
					return Optional.ofNullable(time).map(OffsetDateTime::toInstant);
				}).single();
		if (consumedAt.isEmpty()) {
			return Optional.empty();
		}
		var stored = find(userId).orElseThrow(() -> new IllegalStateException("TOTP consumption was not stored"));
		if (!stored.factorId().equals(factorId) || !stored.active() || !Long.valueOf(step).equals(stored.lastUsedStep())) {
			throw new IllegalStateException("TOTP consumption was not stored");
		}
		return consumedAt;
	}

	public boolean cancel(UUID userId, UUID factorId) {
		boolean expected = find(userId).filter(factor -> factor.factorId().equals(factorId) && !factor.active()).isPresent();
		int changed = this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :userId AND factor_id = :factorId AND status = 'pending'")
				.param("userId", userId).param("factorId", factorId).update();
		if ((expected && changed != 1) || (changed == 1 && find(userId).isPresent())) {
			throw new IllegalStateException("TOTP enrollment was not cancelled");
		}
		return changed == 1;
	}

	public void replaceActive(UUID userId, UUID oldFactorId, Replacement replacement, long step, Instant activatedAt, long nextVersion) {
		requireOne(this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :userId AND factor_id = :factorId AND status = 'active'")
				.param("userId", userId).param("factorId", oldFactorId).update());
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_user_totp (user_id, factor_id, secret_ciphertext, key_id, enrollment_credential_version,
				    status, issued_at, expires_at, activated_at, last_used_step)
				VALUES (:userId, :factorId, :secret, :keyId, :version, 'active', :issuedAt, :expiresAt, :activatedAt, :step)
				""").param("userId", userId).param("factorId", replacement.factorId()).param("secret", replacement.ciphertext())
				.param("keyId", replacement.keyId()).param("version", nextVersion).param("issuedAt", at(replacement.issuedAt()))
				.param("expiresAt", at(replacement.expiresAt())).param("activatedAt", at(activatedAt)).param("step", step).update());
		boolean stored = this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_user_totp WHERE user_id = :userId AND factor_id = :factorId
				    AND secret_ciphertext = :secret AND key_id = :keyId AND enrollment_credential_version = :version
				    AND status = 'active' AND issued_at = :issuedAt AND expires_at = :expiresAt
				    AND activated_at = :activatedAt AND last_used_step = :step)
				""").param("userId", userId).param("factorId", replacement.factorId()).param("secret", replacement.ciphertext())
				.param("keyId", replacement.keyId()).param("version", nextVersion).param("issuedAt", at(replacement.issuedAt()))
				.param("expiresAt", at(replacement.expiresAt())).param("activatedAt", at(activatedAt)).param("step", step)
				.query(Boolean.class).single();
		if (!stored) { throw new IllegalStateException("Replacement TOTP factor was not stored"); }
	}

	private static void requireOne(int changed) {
		if (changed != 1) { throw new IllegalStateException("TOTP factor mutation was not stored"); }
	}

	private static OffsetDateTime at(Instant instant) { return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC); }

	public record Replacement(UUID factorId, String ciphertext, String keyId, Instant issuedAt, Instant expiresAt) {

		@Override
		public String toString() { return "Replacement[factorId=" + this.factorId + ", secret=REDACTED]"; }
	}

	public record Factor(UUID factorId, String encryptedSecret, String keyId, long enrollmentCredentialVersion,
			boolean active, Long lastUsedStep, boolean unexpired, Instant now) {

		@Override
		public String toString() {
			return "Factor[factorId=" + this.factorId + ", active=" + this.active + ", secret=REDACTED]";
		}

	}

}
