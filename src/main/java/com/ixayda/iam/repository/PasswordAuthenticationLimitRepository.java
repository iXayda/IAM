package com.ixayda.iam.repository;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Callers lock the source bucket, then the account bucket, then the user row. */
@Repository
public class PasswordAuthenticationLimitRepository {

	private final JdbcClient jdbc;

	PasswordAuthenticationLimitRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public int lockLimit(String dimension, String key, int windowSeconds) {
		this.jdbc.sql("""
				INSERT INTO iam_password_authentication_limit (dimension, subject_key)
				VALUES (:dimension, :key) ON CONFLICT DO NOTHING
				""").param("dimension", dimension).param("key", key).update();
		this.jdbc.sql("""
				SELECT subject_key FROM iam_password_authentication_limit
				WHERE dimension = :dimension AND subject_key = :key FOR UPDATE
				""").param("dimension", dimension).param("key", key).query(String.class).single();
		// Read real time only after obtaining the lock, rather than using the transaction start time.
		this.jdbc.sql("""
				UPDATE iam_password_authentication_limit SET failures = 0, window_started_at = clock_timestamp()
				WHERE dimension = :dimension AND subject_key = :key
				    AND window_started_at + :windowSeconds * INTERVAL '1 second' <= clock_timestamp()
				""").param("dimension", dimension).param("key", key).param("windowSeconds", windowSeconds).update();
		return this.jdbc.sql("""
				SELECT failures FROM iam_password_authentication_limit
				WHERE dimension = :dimension AND subject_key = :key
				""").param("dimension", dimension).param("key", key).query(Integer.class).single();
	}

	public void recordFailure(String dimension, String key) {
		int changed = this.jdbc.sql("""
				UPDATE iam_password_authentication_limit SET failures = failures + 1
				WHERE dimension = :dimension AND subject_key = :key
				""").param("dimension", dimension).param("key", key).update();
		requireOne(changed);
	}

	public void clearAccount(String key) {
		int changed = this.jdbc.sql("""
				UPDATE iam_password_authentication_limit SET failures = 0, window_started_at = clock_timestamp()
				WHERE dimension = 'account' AND subject_key = :key
				""").param("key", key).update();
		requireOne(changed);
	}

	private static void requireOne(int changed) {
		if (changed != 1) {
			throw new IllegalStateException("Authentication limit was not stored");
		}
	}

}
