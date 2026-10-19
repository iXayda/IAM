package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Code operations run under the owning user's lock; plaintext never reaches this repository. */
@Repository
public class IdentityMfaRecoveryCodeRepository {

	private final JdbcClient jdbc;

	IdentityMfaRecoveryCodeRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Instant replace(UUID userId, UUID factorId, UUID generationId, List<String> digests) {
		this.jdbc.sql("DELETE FROM iam_mfa_recovery_code WHERE user_id = :userId").param("userId", userId).update();
		Instant issuedAt = this.jdbc.sql("SELECT clock_timestamp()")
				.query((row, index) -> row.getObject(1, OffsetDateTime.class).toInstant()).single();
		for (String digest : digests) {
			requireOne(this.jdbc.sql("""
					INSERT INTO iam_mfa_recovery_code (user_id, factor_id, generation_id, code_digest, issued_at)
					VALUES (:userId, :factorId, :generationId, :digest, :issuedAt)
					""").param("userId", userId).param("factorId", factorId).param("generationId", generationId)
					.param("digest", digest).param("issuedAt", OffsetDateTime.ofInstant(issuedAt, java.time.ZoneOffset.UTC)).update());
		}
		List<String> stored = this.jdbc.sql("""
				SELECT code_digest FROM iam_mfa_recovery_code WHERE user_id = :userId AND factor_id = :factorId
				    AND generation_id = :generationId AND issued_at = :issuedAt AND consumed_at IS NULL ORDER BY code_digest
				""").param("userId", userId).param("factorId", factorId).param("generationId", generationId)
				.param("issuedAt", OffsetDateTime.ofInstant(issuedAt, java.time.ZoneOffset.UTC)).query(String.class).list();
		long total = this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_code WHERE user_id = :userId")
				.param("userId", userId).query(Long.class).single();
		if (total != digests.size() || !stored.equals(digests.stream().sorted().toList())) {
			throw new IllegalStateException("MFA recovery codes were not stored");
		}
		return issuedAt;
	}

	public Optional<Consumption> consume(UUID userId, UUID factorId, String digest) {
		var result = this.jdbc.sql("""
				WITH instant AS MATERIALIZED (SELECT clock_timestamp() AS now)
				UPDATE iam_mfa_recovery_code SET consumed_at = now FROM instant
				WHERE user_id = :userId AND factor_id = :factorId AND code_digest = :digest AND consumed_at IS NULL
				RETURNING generation_id, consumed_at
				""").param("userId", userId).param("factorId", factorId).param("digest", digest)
				.query((row, index) -> new Consumption(row.getObject("generation_id", UUID.class),
						row.getObject("consumed_at", OffsetDateTime.class) == null ? null
								: row.getObject("consumed_at", OffsetDateTime.class).toInstant())).optional();
		if (result.isEmpty()) {
			boolean unconsumed = this.jdbc.sql("""
					SELECT EXISTS (SELECT 1 FROM iam_mfa_recovery_code
					WHERE user_id = :userId AND factor_id = :factorId AND code_digest = :digest AND consumed_at IS NULL)
					""").param("userId", userId).param("factorId", factorId).param("digest", digest)
					.query(Boolean.class).single();
			if (unconsumed) { throw new IllegalStateException("MFA recovery consumption was suppressed"); }
		}
		else {
			if (result.orElseThrow().consumedAt() == null) {
				throw new IllegalStateException("MFA recovery consumption was not stored");
			}
			var stored = this.jdbc.sql("""
					SELECT generation_id, consumed_at FROM iam_mfa_recovery_code
					WHERE user_id = :userId AND factor_id = :factorId AND code_digest = :digest
					""").param("userId", userId).param("factorId", factorId).param("digest", digest)
					.query((row, index) -> new Consumption(row.getObject("generation_id", UUID.class),
							row.getObject("consumed_at", OffsetDateTime.class) == null ? null
									: row.getObject("consumed_at", OffsetDateTime.class).toInstant())).optional();
			if (!result.equals(stored)) { throw new IllegalStateException("MFA recovery consumption was not stored"); }
		}
		return result;
	}

	private static void requireOne(int changed) {
		if (changed != 1) { throw new IllegalStateException("MFA recovery code was not stored"); }
	}

	public record Consumption(UUID generationId, Instant consumedAt) { }

}
