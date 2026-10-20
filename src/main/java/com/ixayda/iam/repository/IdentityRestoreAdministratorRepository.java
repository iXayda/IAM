package com.ixayda.iam.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityRestoreAdministrator;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Offline recovery attribution and one administrator grant per quarantined restore. */
@Repository
public class IdentityRestoreAdministratorRepository {

	private final JdbcClient jdbc;

	IdentityRestoreAdministratorRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Optional<IdentityRestoreAdministrator> find(UUID restoreId) {
		return this.jdbc.sql("SELECT * FROM iam_restore_administrator WHERE restore_id=:id").param("id", restoreId).query((row, index) -> {
			var completed = row.getObject("completed_at", OffsetDateTime.class);
			return new IdentityRestoreAdministrator(row.getObject("restore_id", UUID.class), row.getObject("user_id", UUID.class),
					row.getObject("factor_id", UUID.class), row.getObject("prepared_at", OffsetDateTime.class).toInstant(), completed == null ? null : completed.toInstant());
		}).optional();
	}

	/** No service is admitted while this recovery is pending; all old credentials were invalidated by quarantine. */
	public void clearCandidateCredentials(UUID userId) {
		for (String table : java.util.List.of("iam_user_totp", "iam_password_recovery", "iam_user_setup", "iam_password")) {
			this.jdbc.sql("DELETE FROM " + table + " WHERE user_id=:id").param("id", userId).update();
			if (this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM " + table + " WHERE user_id=:id)").param("id", userId).query(Boolean.class).single()) {
				throw new IllegalStateException("Restore candidate credentials were not cleared");
			}
		}
	}

	public void prepare(UUID restoreId, UUID userId, UUID factorId) {
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_restore_administrator(restore_id,user_id,factor_id) VALUES(:restore,:user,:factor)
				ON CONFLICT(restore_id) DO UPDATE SET factor_id=EXCLUDED.factor_id
				WHERE iam_restore_administrator.user_id=EXCLUDED.user_id AND iam_restore_administrator.completed_at IS NULL
				""").param("restore", restoreId).param("user", userId).param("factor", factorId).update());
		if (!find(restoreId).map(row -> row.userId().equals(userId) && row.factorId().equals(factorId) && row.completedAt() == null).orElse(false)) {
			throw new IllegalStateException("Restore administrator preparation was not stored");
		}
	}

	public void complete(IdentityRestoreAdministrator previous) {
		requireOne(this.jdbc.sql("""
				UPDATE iam_restore_administrator SET completed_at=GREATEST(clock_timestamp(),prepared_at)
				WHERE restore_id=:restore AND user_id=:user AND factor_id=:factor AND completed_at IS NULL
				""").param("restore", previous.restoreId()).param("user", previous.userId()).param("factor", previous.factorId()).update());
		var stored = find(previous.restoreId()).orElseThrow();
		if (!stored.userId().equals(previous.userId()) || !stored.factorId().equals(previous.factorId()) || stored.completedAt() == null) {
			throw new IllegalStateException("Restore administrator completion was not stored");
		}
		requireOne(this.jdbc.sql("INSERT INTO iam_administrator(user_id,granted_at) VALUES(:user,:at)")
				.param("user", stored.userId()).param("at", OffsetDateTime.ofInstant(stored.completedAt(), java.time.ZoneOffset.UTC)).update());
		if (!this.jdbc.sql("SELECT granted_at=:at FROM iam_administrator WHERE user_id=:user")
				.param("user", stored.userId()).param("at", OffsetDateTime.ofInstant(stored.completedAt(), java.time.ZoneOffset.UTC)).query(Boolean.class).single()) {
			throw new IllegalStateException("Restored administrator grant was not stored");
		}
	}

	private static void requireOne(int changed) { if (changed != 1) { throw new IllegalStateException("Restored administrator mutation was not stored"); } }
}
