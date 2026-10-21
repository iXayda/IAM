package com.ixayda.iam.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Maintenance selection never treats a spent refresh token as an expired authorization family. */
@Repository
public class IdentityProtocolCleanupRepository {

	private static final String FROM = """
			FROM oauth2_authorization a
			LEFT JOIN iam_authorization_binding b ON b.authorization_id=a.id
			LEFT JOIN iam_refresh_family f ON f.authorization_id=a.id
			""";
	private static final String ELIGIBLE = """
			WHERE GREATEST(a.authorization_code_expires_at,a.access_token_expires_at,a.oidc_id_token_expires_at,
			    a.refresh_token_expires_at,b.code_expires_at,f.absolute_expires_at) < clock_timestamp() - INTERVAL '330 seconds'
			AND (a.authorization_code_value IS NULL OR a.authorization_code_expires_at IS NOT NULL)
			AND (a.access_token_value IS NULL OR a.access_token_expires_at IS NOT NULL)
			AND (a.oidc_id_token_value IS NULL OR a.oidc_id_token_expires_at IS NOT NULL)
			AND (a.refresh_token_value IS NULL OR (a.refresh_token_expires_at IS NOT NULL AND f.authorization_id IS NOT NULL))
			""";
	private final JdbcClient jdbc;

	IdentityProtocolCleanupRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public void requireDatabaseOwner() {
		if (!this.jdbc.sql("SELECT current_user=session_user AND current_user=pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")
				.query(Boolean.class).single()) { throw new IllegalStateException("Protocol cleanup requires the database owner"); }
	}

	public void boundStatements(long milliseconds) {
		this.jdbc.sql("SELECT set_config('statement_timeout',:timeout,true),set_config('lock_timeout','250ms',true)")
				.param("timeout", milliseconds + "ms").query().singleRow();
	}

	/** Continue past examined ids without locking candidates or revisiting busy grants in this run. */
	public List<UUID> candidates(int maximum, UUID after) {
		String position = after == null ? "" : " AND a.id > :after";
		var query = this.jdbc.sql("SELECT a.id " + FROM + ELIGIBLE + position + " ORDER BY a.id LIMIT :maximum").param("maximum", maximum);
		if (after != null) { query.param("after", after.toString()); }
		return query.query((row, index) -> UUID.fromString(row.getString(1))).list();
	}

	/** Same advisory domain as native protocol writes, then the same parent rows; never wait on a busy grant. */
	public boolean tryLock(UUID id) {
		if (!this.jdbc.sql("SELECT pg_try_advisory_xact_lock(hashtextextended(:id,762941))").param("id", id.toString()).query(Boolean.class).single()) { return false; }
		return !this.jdbc.sql("SELECT a.id FROM oauth2_authorization a JOIN iam_authorization_record r ON r.id=a.id WHERE a.id=:id FOR UPDATE OF a,r SKIP LOCKED")
				.param("id", id.toString()).query(String.class).list().isEmpty();
	}

	/** Fresh statement after locks, including the complete family bound and every emitted token. */
	public boolean isEligible(UUID id) {
		return !this.jdbc.sql("SELECT a.id " + FROM + ELIGIBLE + " AND a.id=:id")
				.param("id", id.toString()).query(String.class).list().isEmpty();
	}

	/** Current-pointer FK is deferred; the complete parent chain is removed in one statement. */
	public void removeDependencies(UUID id) {
		for (String table : List.of("iam_refresh_history", "iam_refresh_family", "iam_authorization_binding")) {
			long expected = this.jdbc.sql("SELECT count(*) FROM " + table + " WHERE authorization_id=:id").param("id", id.toString()).query(Long.class).single();
			int changed = this.jdbc.sql("DELETE FROM " + table + " WHERE authorization_id=:id").param("id", id.toString()).update();
			if (changed != expected || this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM " + table + " WHERE authorization_id=:id)").param("id", id.toString()).query(Boolean.class).single()) {
				throw new IllegalStateException("Protocol cleanup was not stored");
			}
		}
		if (this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_authorization_binding_role WHERE authorization_id=:id)").param("id", id.toString()).query(Boolean.class).single()) {
			throw new IllegalStateException("Protocol cleanup was not stored");
		}
	}

	public int expiredInteractions(int maximum) {
		return this.jdbc.sql("SELECT count(*) FROM (SELECT id FROM iam_authorization_interaction WHERE expires_at <= clock_timestamp() LIMIT :maximum) expired")
				.param("maximum", maximum).query(Integer.class).single();
	}
}
