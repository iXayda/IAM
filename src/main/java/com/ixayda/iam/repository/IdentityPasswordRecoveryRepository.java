package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** The caller holds the owning user's lock for every recovery operation. */
@Repository
public class IdentityPasswordRecoveryRepository {

	private final JdbcClient jdbc;

	IdentityPasswordRecoveryRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Instant issue(UUID userId, String digest, long version) {
		Instant expires = this.jdbc.sql("""
				WITH instant AS (SELECT clock_timestamp() AS now)
				INSERT INTO iam_password_recovery (user_id, token_digest, credential_version, status, issued_at, expires_at, finished_at)
				SELECT :user, :digest, :version, 'issued', now, now + INTERVAL '30 minutes', NULL FROM instant
				ON CONFLICT (user_id) DO UPDATE SET token_digest = EXCLUDED.token_digest,
				    credential_version = EXCLUDED.credential_version, status = 'issued', issued_at = EXCLUDED.issued_at,
				    expires_at = EXCLUDED.expires_at, finished_at = NULL
				RETURNING expires_at
				""").param("user", userId).param("digest", digest).param("version", version)
				.query((row, index) -> row.getObject("expires_at", OffsetDateTime.class).toInstant()).single();
		if (!isUsable(userId, digest, version)) {
			throw new IllegalStateException("Password recovery was not stored");
		}
		return expires;
	}

	public boolean isUsable(UUID userId, String digest, long version) {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_password_recovery WHERE user_id = :user AND token_digest = :digest
				    AND credential_version = :version AND status = 'issued' AND expires_at > clock_timestamp())
				""").param("user", userId).param("digest", digest).param("version", version).query(Boolean.class).single();
	}

	public boolean consume(UUID userId, String digest, long version) {
		int changed = this.jdbc.sql("""
				UPDATE iam_password_recovery SET status = 'consumed', finished_at = clock_timestamp()
				WHERE user_id = :user AND token_digest = :digest AND credential_version = :version
				    AND status = 'issued' AND expires_at > clock_timestamp()
				""").param("user", userId).param("digest", digest).param("version", version).update();
		if (changed == 0) {
			// A deadline crossed during password storage is an ordinary denial; the caller rolls back the replacement.
			if (isUsable(userId, digest, version)) {
				throw new IllegalStateException("Password recovery was not consumed");
			}
			return false;
		}
		requireFinished(userId, digest, version, "consumed");
		return true;
	}

	public void cancel(UUID userId) {
		var proof = this.jdbc.sql("SELECT token_digest, credential_version FROM iam_password_recovery WHERE user_id = :user AND status = 'issued'")
				.param("user", userId).query((row, index) -> new OutstandingProof(row.getString("token_digest"), row.getLong("credential_version")))
				.optional().orElseThrow(() -> new IllegalStateException("No outstanding password recovery"));
		int changed = this.jdbc.sql("""
				UPDATE iam_password_recovery SET status = 'cancelled', finished_at = clock_timestamp()
				WHERE user_id = :user AND status = 'issued'
				""").param("user", userId).update();
		if (changed != 1) {
			throw new IllegalStateException("Password recovery was not cancelled");
		}
		requireFinished(userId, proof.digest(), proof.version(), "cancelled");
	}

	private void requireFinished(UUID userId, String digest, long version, String status) {
		boolean stored = this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_password_recovery WHERE user_id = :user AND token_digest = :digest
				    AND credential_version = :version AND status = :status AND finished_at IS NOT NULL)
				""").param("user", userId).param("digest", digest).param("version", version).param("status", status)
				.query(Boolean.class).single();
		if (!stored) {
			throw new IllegalStateException("Password recovery state was not stored");
		}
	}

	private record OutstandingProof(String digest, long version) { }

}
