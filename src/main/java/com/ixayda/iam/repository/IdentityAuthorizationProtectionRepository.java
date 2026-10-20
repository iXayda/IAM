package com.ixayda.iam.repository;

import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Deployment identity is readable by Web and writable only by the maintenance owner. */
@Repository
public class IdentityAuthorizationProtectionRepository {

	private final JdbcClient jdbc;

	IdentityAuthorizationProtectionRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Optional<String> keyId() {
		return this.jdbc.sql("SELECT key_id FROM iam_authorization_protection WHERE singleton=1").query(String.class).optional();
	}

	public void lockForInstallation() {
		if (!this.jdbc.sql("SELECT current_user=session_user AND current_user=pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")
				.query(Boolean.class).single()) { throw new IllegalStateException("Authorization protection installation requires the database owner"); }
		this.jdbc.sql("SELECT singleton FROM iam_authorization_protection WHERE singleton=1 FOR UPDATE").query(Integer.class).single();
	}

	public void initialize(String keyId) {
		int changed = this.jdbc.sql("""
				UPDATE iam_authorization_protection SET key_id=:key WHERE singleton=1 AND key_id IS NULL
				AND NOT EXISTS (SELECT 1 FROM oauth2_authorization)
				AND NOT EXISTS (SELECT 1 FROM iam_authorization_interaction)
				""").param("key", keyId).update();
		if (changed != 1 || !keyId().equals(Optional.of(keyId))) { throw new IllegalStateException("Authorization protection must be initialized before protocol use"); }
	}
}
