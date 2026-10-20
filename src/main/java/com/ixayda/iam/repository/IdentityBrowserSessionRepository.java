package com.ixayda.iam.repository;

import java.sql.Types;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityBrowserSessionPage;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Lifecycle checks around the official JDBC session repository; callers own the transaction. */
@Repository
public class IdentityBrowserSessionRepository {

	private final JdbcClient jdbc;

	IdentityBrowserSessionRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public boolean lock(String id) {
		return this.jdbc.sql("SELECT primary_id FROM iam_browser_session WHERE session_id = :id FOR UPDATE")
				.param("id", id).query(String.class).optional().isPresent();
	}

	/** Cookie rotation preserves this internal key. Callers read the current cookie id only after this lock. */
	public boolean lockByPrimaryId(UUID id) {
		return this.jdbc.sql("SELECT primary_id FROM iam_browser_session WHERE primary_id=:id FOR UPDATE")
				.param("id", id.toString()).query(String.class).optional().isPresent();
	}

	public Optional<String> sessionIdByPrimaryId(UUID id) {
		return this.jdbc.sql("SELECT session_id FROM iam_browser_session WHERE primary_id=:id")
				.param("id", id.toString()).query(String.class).optional();
	}

	public Optional<UUID> userId(String id) {
		return this.jdbc.sql("SELECT principal_name FROM iam_browser_session WHERE session_id = :id")
				.param("id", id).query(String.class).optional().map(UUID::fromString);
	}

	public boolean ownedAndUnexpired(String id, UUID userId) {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_browser_session WHERE session_id = :id
				AND principal_name = :principal AND expiry_time > extract(epoch FROM clock_timestamp()) * 1000)
				""").param("id", id).param("principal", userId.toString()).query(Boolean.class).single();
	}

	public Optional<Long> ownedSessionExpiry(String id, UUID userId) {
		return this.jdbc.sql("""
				SELECT expiry_time FROM iam_browser_session WHERE session_id = :id
				AND principal_name = :principal AND expiry_time > extract(epoch FROM clock_timestamp()) * 1000
				""").param("id", id).param("principal", userId.toString()).query(Long.class).optional();
	}

	/** Read only after locking the session; a fresh statement observes any change committed during the wait. */
	public Optional<AuthorizationSession> authorizationSession(String id, UUID userId) {
		return this.jdbc.sql("""
				SELECT s.primary_id,s.expiry_time,
				    (SELECT a.attribute_bytes FROM iam_browser_session_attributes a
				        WHERE a.session_primary_id=s.primary_id AND a.attribute_name='iam.authenticatedAt') AS authenticated_at,
				    (SELECT a.attribute_bytes FROM iam_browser_session_attributes a
				        WHERE a.session_primary_id=s.primary_id AND a.attribute_name='iam.credentialVersion') AS credential_version
				FROM iam_browser_session s WHERE s.session_id=:id AND s.principal_name=:principal
				""").param("id", id).param("principal", userId.toString())
				.query((row, index) -> new AuthorizationSession(UUID.fromString(row.getString("primary_id")), row.getLong("expiry_time"),
						row.getBytes("authenticated_at"), row.getBytes("credential_version"))).optional();
	}

	public boolean isBeforeExpiry(long expiryTime) {
		return this.jdbc.sql("SELECT :expiry > extract(epoch FROM clock_timestamp()) * 1000")
				.param("expiry", expiryTime).query(Boolean.class).single();
	}

	public byte[] attribute(String id, String name) {
		return this.jdbc.sql("""
				SELECT a.attribute_bytes FROM iam_browser_session_attributes a
				JOIN iam_browser_session s ON s.primary_id = a.session_primary_id
				WHERE s.session_id = :id AND a.attribute_name = :name
				""").param("id", id).param("name", name).query(byte[].class).optional().orElse(null);
	}

	public void requireStored(String id, UUID userId, long expiryTime) {
		long count = this.jdbc.sql("""
				SELECT count(*) FROM iam_browser_session
				WHERE session_id = :id AND principal_name IS NOT DISTINCT FROM :principal
				AND expiry_time = :expiry
				""").param("id", id).param("principal", userId == null ? null : userId.toString(), Types.VARCHAR)
				.param("expiry", expiryTime)
				.query(Long.class).single();
		if (count != 1) {
			throw new IllegalStateException("Browser session was not stored");
		}
	}

	public void requireDeleted(String id) {
		if (this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE session_id = :id")
				.param("id", id).query(Long.class).single() != 0) {
			throw new IllegalStateException("Browser session was not removed");
		}
	}

	public void deleteAllForUser(UUID userId) {
		this.jdbc.sql("DELETE FROM iam_browser_session WHERE principal_name = :principal")
				.param("principal", userId.toString()).update();
		long remaining = this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :principal")
				.param("principal", userId.toString()).query(Long.class).single();
		if (remaining != 0) {
			throw new IllegalStateException("Browser sessions were not revoked");
		}
	}

	/** Only public columns and primitive authentication encodings are selected; never read cookie ids or security contexts. */
	public List<Listing> searchForUser(UUID userId, String currentSession, byte[] credentialVersion, int limit, IdentityBrowserSessionPage.Cursor after) {
		String position = after == null ? "" : " AND (s.creation_time,s.primary_id) > (:created,:after)";
		var query = this.jdbc.sql("""
				SELECT s.primary_id,s.creation_time,s.last_access_time,s.expiry_time,t.attribute_bytes AS authenticated_at,
				    s.session_id=:current AS current_session
				FROM iam_browser_session s JOIN iam_browser_session_attributes t ON t.session_primary_id=s.primary_id AND t.attribute_name='iam.authenticatedAt'
				JOIN iam_browser_session_attributes v ON v.session_primary_id=s.primary_id AND v.attribute_name='iam.credentialVersion'
				WHERE s.principal_name=:owner AND v.attribute_bytes=:version AND s.expiry_time > extract(epoch FROM clock_timestamp()) * 1000
				""" + position + " ORDER BY s.creation_time,s.primary_id LIMIT :limit")
				.param("owner", userId.toString()).param("current", currentSession).param("version", credentialVersion).param("limit", limit);
		if (after != null) { query.param("created", after.createdAt().toEpochMilli()).param("after", after.id().toString()); }
		return query.query((row, index) -> new Listing(UUID.fromString(row.getString("primary_id")), Instant.ofEpochMilli(row.getLong("creation_time")),
				Instant.ofEpochMilli(row.getLong("last_access_time")), row.getLong("expiry_time"), row.getBytes("authenticated_at"), row.getBoolean("current_session"))).list();
	}

	public boolean isOwnedByPrimaryId(UUID id, UUID userId) {
		return this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_browser_session WHERE primary_id=:id AND principal_name=:owner)")
				.param("id", id.toString()).param("owner", userId.toString()).query(Boolean.class).single();
	}

	/** The workflow holds the owner and session locks; verify deletion instead of trusting an affected-row count. */
	public void deleteOwnedByPrimaryId(UUID id, UUID userId) {
		int deleted = this.jdbc.sql("DELETE FROM iam_browser_session WHERE primary_id=:id AND principal_name=:owner")
				.param("id", id.toString()).param("owner", userId.toString()).update();
		if (deleted != 1 || this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_browser_session WHERE primary_id=:id)")
				.param("id", id.toString()).query(Boolean.class).single()
				|| this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_browser_session_attributes WHERE session_primary_id=:id)")
						.param("id", id.toString()).query(Boolean.class).single()) { throw new IllegalStateException("Browser session was not revoked"); }
	}

	public record Listing(UUID id, Instant createdAt, Instant lastAccessedAt, long idleExpiry, byte[] authenticatedAt, boolean current) {
		@Override public String toString() { return "BrowserSessionListing[REDACTED]"; }
	}

	public record AuthorizationSession(UUID id, long idleExpiry, byte[] authenticatedAt, byte[] credentialVersion) {
		@Override
		public String toString() { return "AuthorizationSession[REDACTED]"; }
	}

}
