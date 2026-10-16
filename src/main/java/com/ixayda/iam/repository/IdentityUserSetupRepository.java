package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** All mutations are serialized by the workflow's lock on the owning user. */
@Repository
public class IdentityUserSetupRepository {

	private final JdbcClient jdbc;

	IdentityUserSetupRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Instant issue(UUID userId, String digest) {
		var issuance = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				INSERT INTO iam_user_setup (user_id, token_digest, status, issued_at, expires_at, finished_at)
				SELECT :userId, :digest, 'issued', now, now + INTERVAL '30 minutes', NULL FROM instant
				ON CONFLICT (user_id) DO UPDATE SET token_digest = EXCLUDED.token_digest, status = 'issued',
				    issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, finished_at = NULL
				RETURNING expires_at, (SELECT now FROM instant) AS expected_issued_at
				""").param("userId", userId).param("digest", digest)
				.query((row, index) -> new Issuance(row.getObject("expected_issued_at", OffsetDateTime.class),
						row.getObject("expires_at", OffsetDateTime.class))).single();
		boolean stored = this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_user_setup WHERE user_id = :userId AND token_digest = :digest
				    AND status = 'issued' AND finished_at IS NULL AND issued_at = :issuedAt
				    AND expires_at = :expiresAt AND expires_at = issued_at + INTERVAL '30 minutes'
				    AND expires_at > clock_timestamp())
				""").param("userId", userId).param("digest", digest)
				.param("issuedAt", issuance.issuedAt()).param("expiresAt", issuance.expiresAt()).query(Boolean.class).single();
		if (!stored) { throw new IllegalStateException("Account setup issuance was not stored"); }
		return issuance.expiresAt().toInstant();
	}

	public boolean isUsable(UUID userId, String digest) {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_user_setup WHERE user_id = :userId AND token_digest = :digest
				    AND status = 'issued' AND expires_at > clock_timestamp())
				""").param("userId", userId).param("digest", digest).query(Boolean.class).single();
	}

	public boolean consume(UUID userId, String digest) {
		return this.jdbc.sql("""
				UPDATE iam_user_setup SET status = 'consumed', finished_at = clock_timestamp()
				WHERE user_id = :userId AND token_digest = :digest AND status = 'issued'
				    AND expires_at > clock_timestamp()
				""").param("userId", userId).param("digest", digest).update() == 1;
	}

	public boolean cancel(UUID userId) {
		return this.jdbc.sql("""
				UPDATE iam_user_setup SET status = 'cancelled', finished_at = clock_timestamp()
				WHERE user_id = :userId AND status = 'issued'
				""").param("userId", userId).update() == 1;
	}

	private record Issuance(OffsetDateTime issuedAt, OffsetDateTime expiresAt) { }

}
