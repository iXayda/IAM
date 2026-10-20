package com.ixayda.iam.repository;

import java.sql.Types;
import java.util.Optional;
import java.util.UUID;

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

	public record AuthorizationSession(UUID id, long idleExpiry, byte[] authenticatedAt, byte[] credentialVersion) {
		@Override
		public String toString() { return "AuthorizationSession[REDACTED]"; }
	}

}
