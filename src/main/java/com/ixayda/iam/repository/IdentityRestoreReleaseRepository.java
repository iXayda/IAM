package com.ixayda.iam.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityRestoreRelease;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityRestoreReleaseRepository {

	private final JdbcClient jdbc;

	IdentityRestoreReleaseRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Optional<IdentityRestoreRelease> find(UUID restoreId) {
		return this.jdbc.sql("SELECT * FROM iam_restore_release WHERE restore_id=:id").param("id", restoreId)
				.query((row, index) -> new IdentityRestoreRelease(row.getObject("restore_id", UUID.class), row.getObject("user_id", UUID.class),
						row.getObject("factor_id", UUID.class), row.getObject("signing_key_id", UUID.class), row.getObject("released_at", OffsetDateTime.class).toInstant())).optional();
	}

	public IdentityRestoreRelease record(UUID restoreId, UUID userId, UUID factorId, UUID signingKeyId) {
		int changed = this.jdbc.sql("""
				INSERT INTO iam_restore_release(restore_id,user_id,factor_id,signing_key_id,released_at)
				SELECT a.restore_id,a.user_id,a.factor_id,:key,GREATEST(clock_timestamp(),a.completed_at,k.created_at) FROM iam_restore_administrator a
				JOIN iam_restore r ON r.id=a.restore_id JOIN iam_signing_key k ON k.id=:key
				WHERE a.restore_id=:restore AND a.user_id=:user AND a.factor_id=:factor AND a.completed_at IS NOT NULL
				    AND a.completed_at<=clock_timestamp() AND k.created_at>=r.quarantined_at AND k.status='active'
				""").param("restore", restoreId).param("user", userId).param("factor", factorId).param("key", signingKeyId).update();
		var stored = find(restoreId).orElseThrow(() -> new IllegalStateException("Restore release was not stored"));
		boolean accurate = this.jdbc.sql("""
				SELECT l.user_id=:user AND l.factor_id=:factor AND l.signing_key_id=:key AND l.released_at>=a.completed_at AND l.released_at>=k.created_at
				FROM iam_restore_release l JOIN iam_restore_administrator a ON a.restore_id=l.restore_id
				JOIN iam_signing_key k ON k.id=l.signing_key_id WHERE l.restore_id=:restore
				""").param("restore", restoreId).param("user", userId).param("factor", factorId).param("key", signingKeyId).query(Boolean.class).single();
		if (changed != 1 || !accurate) { throw new IllegalStateException("Restore release was not stored"); }
		return stored;
	}
}
