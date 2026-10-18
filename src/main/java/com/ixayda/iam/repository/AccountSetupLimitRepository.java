package com.ixayda.iam.repository;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Callers lock the source bucket, then the account bucket, then the user row. */
@Repository
public class AccountSetupLimitRepository {

	private final JdbcClient jdbc;

	AccountSetupLimitRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public int lockLimit(String dimension, String key) {
		// Lock existing buckets during insertion so cleanup cannot remove them before admission.
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_account_setup_limit (dimension, subject_key)
				VALUES (:dimension, :key)
				ON CONFLICT (dimension, subject_key) DO UPDATE SET subject_key = EXCLUDED.subject_key
				""").param("dimension", dimension).param("key", key).update());
		// Read real time only after obtaining the lock, rather than using the transaction start time.
		this.jdbc.sql("""
				UPDATE iam_account_setup_limit SET failures = 0, window_started_at = clock_timestamp()
				WHERE dimension = :dimension AND subject_key = :key
				    AND window_started_at + 900 * INTERVAL '1 second' <= clock_timestamp()
				""").param("dimension", dimension).param("key", key).update();
		return this.jdbc.sql("""
				SELECT failures FROM iam_account_setup_limit
				WHERE dimension = :dimension AND subject_key = :key
				""").param("dimension", dimension).param("key", key).query(Integer.class).single();
	}

	public void recordFailure(String dimension, String key) {
		int expected = failures(dimension, key) + 1;
		int changed = this.jdbc.sql("""
				UPDATE iam_account_setup_limit SET failures = failures + 1
				WHERE dimension = :dimension AND subject_key = :key
				""").param("dimension", dimension).param("key", key).update();
		requireOne(changed);
		if (failures(dimension, key) != expected) { throw new IllegalStateException("Account setup failure budget was not stored"); }
	}

	public void clearAccount(String key) {
		int changed = this.jdbc.sql("""
				UPDATE iam_account_setup_limit SET failures = 0, window_started_at = clock_timestamp()
				WHERE dimension = 'account' AND subject_key = :key
				""").param("key", key).update();
		requireOne(changed);
		if (failures("account", key) != 0) { throw new IllegalStateException("Account setup failure budget was not cleared"); }
	}

	private int failures(String dimension, String key) {
		return this.jdbc.sql("SELECT failures FROM iam_account_setup_limit WHERE dimension = :dimension AND subject_key = :key")
				.param("dimension", dimension).param("key", key).query(Integer.class).single();
	}

	public void cleanUpExpired() {
		this.jdbc.sql("""
				WITH expired AS (
				    SELECT dimension, subject_key FROM iam_account_setup_limit
				    WHERE window_started_at < clock_timestamp() - INTERVAL '1 day'
				    ORDER BY window_started_at LIMIT 1000 FOR UPDATE SKIP LOCKED
				)
				DELETE FROM iam_account_setup_limit current USING expired
				WHERE current.dimension = expired.dimension AND current.subject_key = expired.subject_key
				""").update();
	}

	private static void requireOne(int changed) {
		if (changed != 1) {
			throw new IllegalStateException("Authentication limit was not stored");
		}
	}

}
