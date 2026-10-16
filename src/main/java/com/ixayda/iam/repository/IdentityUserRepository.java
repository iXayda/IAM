package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityUser;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityUserRepository {

	private final JdbcClient jdbc;

	IdentityUserRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public IdentityUser create(UUID id, String username, String displayName) {
		return this.jdbc.sql("""
				INSERT INTO iam_user (id, username, display_name) VALUES (:id, :username, :displayName)
				RETURNING id, username, display_name, status, created_at
				""").param("id", id).param("username", username).param("displayName", displayName)
				.query(IdentityUserRepository::mapUser).single();
	}

	public Optional<IdentityUser> findById(UUID id) {
		return this.jdbc.sql("SELECT id, username, display_name, status, created_at FROM iam_user WHERE id = :id")
				.param("id", id).query(IdentityUserRepository::mapUser).optional();
	}

	public Optional<IdentityUser> findByUsername(String username) {
		return this.jdbc.sql("""
				SELECT id, username, display_name, status, created_at FROM iam_user WHERE username = :username
				""").param("username", username).query(IdentityUserRepository::mapUser).optional();
	}

	public Optional<IdentityUser> lockById(UUID id) {
		return this.jdbc.sql("""
				SELECT id, username, display_name, status, created_at FROM iam_user WHERE id = :id FOR UPDATE
				""").param("id", id).query(IdentityUserRepository::mapUser).optional();
	}

	public void insertPassword(UUID id, String hash) {
		int changed = this.jdbc.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)")
				.param("id", id).param("hash", hash).update();
		if (changed != 1 || !this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id")
				.param("id", id).query(String.class).optional().equals(Optional.of(hash))) {
			throw new IllegalStateException("Initial password was not stored");
		}
	}

	public boolean hasPassword(UUID id) {
		return this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM iam_password WHERE user_id = :id)")
				.param("id", id).query(Boolean.class).single();
	}

	public void activateAfterSetup(UUID id) {
		int updated = this.jdbc.sql("""
				UPDATE iam_user SET status = 'active' WHERE id = :id AND status = 'pending'
				    AND EXISTS (SELECT 1 FROM iam_password WHERE user_id = :id)
				    AND EXISTS (SELECT 1 FROM iam_user_setup WHERE user_id = :id AND status = 'consumed')
				""").param("id", id).update();
		if (updated != 1 || findById(id).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()) {
			throw new IllegalStateException("Account setup did not activate the user");
		}
	}

	private static IdentityUser mapUser(ResultSet result, int row) throws SQLException {
		return new IdentityUser(result.getObject("id", UUID.class), result.getString("username"),
				result.getString("display_name"), IdentityUser.Status.valueOf(result.getString("status").toUpperCase(Locale.ROOT)),
				result.getObject("created_at", OffsetDateTime.class).toInstant());
	}

}
