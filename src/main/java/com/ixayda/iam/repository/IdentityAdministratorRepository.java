package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministrator;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Mutations hold the affected user lock, then the singleton lifecycle lock. */
@Repository
public class IdentityAdministratorRepository {

	private final JdbcClient jdbc;

	IdentityAdministratorRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public Optional<IdentityAdministrator> find(UUID userId) {
		return this.jdbc.sql("SELECT user_id, granted_at FROM iam_administrator WHERE user_id = :id")
				.param("id", userId).query((row, index) -> new IdentityAdministrator(row.getObject("user_id", UUID.class),
						row.getObject("granted_at", OffsetDateTime.class).toInstant())).optional();
	}

	public Lifecycle lockLifecycle() {
		return this.jdbc.sql("SELECT completed_at, revision, candidate_user_id FROM iam_admin_bootstrap WHERE singleton = 1 FOR UPDATE")
				.query((row, index) -> new Lifecycle(row.getObject("completed_at", OffsetDateTime.class) != null,
						row.getLong("revision"), row.getObject("candidate_user_id", UUID.class))).single();
	}

	public void reserveCandidate(UUID userId, long revision) {
		long next = Math.addExact(revision, 1);
		requireOne(this.jdbc.sql("""
				UPDATE iam_admin_bootstrap SET candidate_user_id = :id, revision = :next
				WHERE singleton = 1 AND completed_at IS NULL AND candidate_user_id IS NULL AND revision = :revision
				""").param("id", userId).param("next", next).param("revision", revision).update());
		var stored = lockLifecycle();
		if (stored.completed() || stored.revision() != next || !userId.equals(stored.candidateUserId())) {
			throw new IllegalStateException("Administrator candidate was not stored");
		}
	}

	public boolean hasAdministrators() {
		return this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM iam_administrator)").query(Boolean.class).single();
	}

	public boolean hasCurrentAuthentication(UUID userId, UUID factorId, long credentialVersion) {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_administrator a JOIN iam_user u ON u.id = a.user_id
				    JOIN iam_password p ON p.user_id = u.id JOIN iam_user_totp t ON t.user_id = u.id
				    WHERE u.id = :id AND u.status = 'active' AND p.credential_version = :version
				    AND t.status = 'active' AND t.factor_id = :factor)
				""").param("id", userId).param("factor", factorId).param("version", credentialVersion).query(Boolean.class).single();
	}

	/** Structural availability is independent of paging, sessions, and temporary failure budgets. */
	public boolean hasOtherUsableAdministrator(UUID userId) {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_administrator a JOIN iam_user u ON u.id = a.user_id
				    JOIN iam_password p ON p.user_id = u.id JOIN iam_user_totp t ON t.user_id = u.id
				    WHERE a.user_id <> :id AND u.status = 'active' AND t.status = 'active')
				""").param("id", userId).query(Boolean.class).single();
	}

	public void completeBootstrap(UUID userId, long revision) {
		requireOne(this.jdbc.sql("""
				UPDATE iam_admin_bootstrap SET completed_at = clock_timestamp(), initial_user_id = :id, revision = :next
				WHERE singleton = 1 AND completed_at IS NULL AND revision = :revision
				    AND (candidate_user_id IS NULL OR candidate_user_id = :id)
				""").param("id", userId).param("revision", revision).param("next", Math.addExact(revision, 1)).update());
		Instant completedAt = this.jdbc.sql("SELECT completed_at FROM iam_admin_bootstrap WHERE singleton = 1 AND initial_user_id = :id AND revision = :next")
				.param("id", userId).param("next", Math.addExact(revision, 1))
				.query((row, index) -> row.getObject(1, OffsetDateTime.class) == null ? null : row.getObject(1, OffsetDateTime.class).toInstant())
				.optional().orElseThrow(() -> new IllegalStateException("Administrator initialization was not closed"));
		requireOne(this.jdbc.sql("INSERT INTO iam_administrator (user_id, granted_at) VALUES (:id, :at)")
				.param("id", userId).param("at", OffsetDateTime.ofInstant(completedAt, java.time.ZoneOffset.UTC)).update());
		if (!find(userId).map(value -> value.grantedAt().equals(completedAt)).orElse(false)) {
			throw new IllegalStateException("Administrator was not stored");
		}
	}

	/** A real write makes stale repeatable-read/serializable callers fail rather than count an old snapshot. */
	public void advanceRevision(long revision) {
		long next = Math.addExact(revision, 1);
		requireOne(this.jdbc.sql("UPDATE iam_admin_bootstrap SET revision = :next WHERE singleton = 1 AND revision = :revision")
				.param("next", next).param("revision", revision).update());
		long stored = this.jdbc.sql("SELECT revision FROM iam_admin_bootstrap WHERE singleton = 1").query(Long.class).single();
		if (stored != next) { throw new IllegalStateException("Administrator lifecycle was not stored"); }
	}

	private static void requireOne(int changed) {
		if (changed != 1) { throw new IllegalStateException("Administrator lifecycle mutation was not stored"); }
	}

	public record Lifecycle(boolean completed, long revision, UUID candidateUserId) { }

}
