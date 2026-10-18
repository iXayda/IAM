package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserPage;

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

	public List<IdentityUser> search(String keyword, IdentityUser.Status status, int limit, IdentityUserPage.Cursor after) {
		var sql = new StringBuilder("SELECT id, username, display_name, status, created_at FROM iam_user WHERE 1 = 1");
		if (!keyword.isEmpty()) {
			sql.append(" AND (strpos(username, :usernameKeyword) > 0 OR strpos(display_name COLLATE \"C\", :keyword) > 0)");
		}
		if (status != null) {
			sql.append(" AND status = :status");
		}
		if (after != null) {
			sql.append(" AND (created_at, id) > (:createdAt, :id)");
		}
		sql.append(" ORDER BY created_at, id LIMIT :limit");
		var query = this.jdbc.sql(sql.toString()).param("limit", limit);
		if (!keyword.isEmpty()) {
			query.param("usernameKeyword", keyword.toLowerCase(Locale.ROOT)).param("keyword", keyword);
		}
		if (status != null) {
			query.param("status", status.name().toLowerCase(Locale.ROOT));
		}
		if (after != null) {
			query.param("createdAt", OffsetDateTime.ofInstant(after.createdAt(), ZoneOffset.UTC)).param("id", after.id());
		}
		return query.query(IdentityUserRepository::mapUser).list();
	}

	public Optional<IdentityUser> lockById(UUID id) {
		return this.jdbc.sql("""
				SELECT id, username, display_name, status, created_at FROM iam_user WHERE id = :id FOR UPDATE
				""").param("id", id).query(IdentityUserRepository::mapUser).optional();
	}

	public Optional<IdentityUser> lockByUsername(String username) {
		return this.jdbc.sql("""
				SELECT id, username, display_name, status, created_at FROM iam_user WHERE username = :username FOR UPDATE
				""").param("username", username).query(IdentityUserRepository::mapUser).optional();
	}

	public Optional<String> findPasswordHash(UUID id) {
		return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id")
				.param("id", id).query(String.class).optional();
	}

	public Optional<Long> findPasswordVersion(UUID id) {
		return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id")
				.param("id", id).query(Long.class).optional();
	}

	public boolean hasCurrentPasswordVersion(UUID id, long version) {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_user u JOIN iam_password p ON p.user_id = u.id
				WHERE u.id = :id AND u.status = 'active' AND p.credential_version = :version)
				""").param("id", id).param("version", version).query(Boolean.class).single();
	}

	public void updateDisplayName(UUID id, String displayName) {
		int updated = this.jdbc.sql("UPDATE iam_user SET display_name = :displayName WHERE id = :id")
				.param("id", id).param("displayName", displayName).update();
		if (updated != 1 || findById(id).filter(user -> user.displayName().equals(displayName)).isEmpty()) {
			throw new IllegalStateException("Display name update was not stored");
		}
	}

	public void replacePassword(UUID id, String hash, long version) {
		int updated = this.jdbc.sql("""
				UPDATE iam_password SET password_hash = :hash, credential_version = credential_version + 1
				WHERE user_id = :id AND credential_version = :version
				""").param("id", id).param("hash", hash).param("version", version).update();
		if (updated != 1 || !findPasswordHash(id).filter(hash::equals).isPresent()
				|| !findPasswordVersion(id).filter(stored -> stored == Math.addExact(version, 1)).isPresent()) {
			throw new IllegalStateException("Password change was not stored");
		}
	}

	public void insertPassword(UUID id, String hash) {
		int changed = this.jdbc.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)")
				.param("id", id).param("hash", hash).update();
		if (changed != 1 || !findPasswordHash(id).equals(Optional.of(hash)) || !findPasswordVersion(id).equals(Optional.of(1L))) {
			throw new IllegalStateException("Initial password was not stored");
		}
	}

	public boolean hasPassword(UUID id) {
		return this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM iam_password WHERE user_id = :id)")
				.param("id", id).query(Boolean.class).single();
	}

	/** Called under the user lock; invalidates authentication evidence without changing the password. */
	public void disable(UUID id) {
		var version = findPasswordVersion(id);
		if (version.isPresent()) {
			long expected = Math.addExact(version.orElseThrow(), 1);
			int changed = this.jdbc.sql("UPDATE iam_password SET credential_version = :next WHERE user_id = :id AND credential_version = :previous")
					.param("next", expected).param("id", id).param("previous", version.orElseThrow()).update();
			if (changed != 1 || !findPasswordVersion(id).equals(Optional.of(expected))) {
				throw new IllegalStateException("Authentication invalidation was not stored");
			}
		}
		int changed = this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id AND status IN ('pending', 'active')")
				.param("id", id).update();
		requireStatus(id, changed, IdentityUser.Status.DISABLED);
	}

	/** Password possession alone cannot replace evidence of completed controlled setup. */
	public void enable(UUID id) {
		boolean completed = this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_user_setup s JOIN iam_password p ON p.user_id = s.user_id
				WHERE s.user_id = :id AND s.status = 'consumed')
				""").param("id", id).query(Boolean.class).single();
		var status = completed ? IdentityUser.Status.ACTIVE : IdentityUser.Status.PENDING;
		int changed = this.jdbc.sql("UPDATE iam_user SET status = :status WHERE id = :id AND status = 'disabled'")
				.param("status", status.name().toLowerCase(Locale.ROOT)).param("id", id).update();
		requireStatus(id, changed, status);
	}

	private void requireStatus(UUID id, int changed, IdentityUser.Status expected) {
		if (changed != 1 || findById(id).filter(user -> user.status() == expected).isEmpty()) {
			throw new IllegalStateException("Account state change was not stored");
		}
	}

	public void activateAfterSetup(UUID id) {
		int updated = this.jdbc.sql("""
				UPDATE iam_user SET status = 'active' WHERE id = :id AND status = 'pending'
				    AND EXISTS (SELECT 1 FROM iam_password WHERE user_id = :id)
				    AND EXISTS (SELECT 1 FROM iam_user_setup WHERE user_id = :id AND status = 'consumed')
				""").param("id", id).update();
		requireStatus(id, updated, IdentityUser.Status.ACTIVE);
	}

	private static IdentityUser mapUser(ResultSet result, int row) throws SQLException {
		return new IdentityUser(result.getObject("id", UUID.class), result.getString("username"),
				result.getString("display_name"), IdentityUser.Status.valueOf(result.getString("status").toUpperCase(Locale.ROOT)),
				result.getObject("created_at", OffsetDateTime.class).toInstant());
	}

}
