package com.ixayda.iam.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class UserSessionSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID DEFAULT_TENANT_ID =
			UUID.fromString("00000000-0000-0000-0000-000000000001");

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e31");

	private static final UUID USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e32");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e33");

	private static final UUID UNKNOWN_USER_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e34");

	private static final UUID SESSION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e35");

	private static final UUID SECOND_SESSION_ID =
			UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e36");

	private static final OffsetDateTime AUTHENTICATED_AT =
			OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);

	private static final OffsetDateTime EXPIRES_AT = AUTHENTICATED_AT.plusHours(8);

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE session_id IN (:sessionId, :secondSessionId)")
			.param("sessionId", SESSION_ID)
			.param("secondSessionId", SECOND_SESSION_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:userId, :secondUserId)")
			.param("userId", USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesTenantScopedSessionMetadataAndLifecycleVersions() {
		insertUser(DEFAULT_TENANT_ID, USER_ID, 0);
		insertTenant();
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID, 7);

		insertSession(DEFAULT_TENANT_ID, SESSION_ID, USER_ID, 0, 0);
		insertSession(SECOND_TENANT_ID, SECOND_SESSION_ID, SECOND_USER_ID, 5, 7);

		assertThat(sessionCount()).isEqualTo(2);
		assertThat(this.jdbcClient.sql("""
				SELECT authentication_method = 'password'
				   AND status = 'active'
				   AND issued_tenant_version = 5
				   AND issued_user_version = 7
				   AND version = 0
				   AND revoked_at IS NULL
				FROM user_sessions
				WHERE tenant_id = :tenantId AND session_id = :sessionId
				""")
			.param("tenantId", SECOND_TENANT_ID)
			.param("sessionId", SECOND_SESSION_ID)
			.query(Boolean.class)
			.single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT indexdef
				FROM pg_indexes
				WHERE schemaname = current_schema() AND tablename = 'user_sessions'
				""").query(String.class).list())
			.anyMatch(definition -> definition.contains(
					"(tenant_id, user_id, status, expires_at, session_id)"))
			.anyMatch(definition -> definition.contains("(expires_at, tenant_id, session_id)"));
	}

	@Test
	void enforcesTenantScopedUserOwnershipAndSessionIdentity() {
		insertTenant();
		insertUser(DEFAULT_TENANT_ID, USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);

		assertThatThrownBy(() -> insertSession(SECOND_TENANT_ID, SESSION_ID, USER_ID, 0, 0))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertSession(DEFAULT_TENANT_ID, SESSION_ID, UNKNOWN_USER_ID, 0, 0))
			.isInstanceOf(DataIntegrityViolationException.class);

		insertSession(DEFAULT_TENANT_ID, SESSION_ID, USER_ID, 0, 0);
		assertThatThrownBy(() -> insertSession(DEFAULT_TENANT_ID, SESSION_ID, USER_ID, 0, 0))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertSession(SECOND_TENANT_ID, SESSION_ID, SECOND_USER_ID, 5, 0))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(sessionCount()).isOne();
	}

	@Test
	void rejectsInvalidSessionLifecycleMetadata() {
		insertUser(DEFAULT_TENANT_ID, USER_ID);

		assertRejected("external", "active", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT, null);
		assertRejected("password", "invalid", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				null);
		assertRejected("password", "active", -1, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				null);
		assertRejected("password", "active", 0, -1, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				null);
		assertRejected("password", "active", 0, 0, -1, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				null);
		assertRejected("password", "active", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT,
				AUTHENTICATED_AT, null);
		assertRejected("password", "active", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT.minusSeconds(1),
				EXPIRES_AT, null);
		assertRejected("password", "active", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				AUTHENTICATED_AT);
		assertRejected("password", "revoked", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				null);
		assertRejected("password", "revoked", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT,
				AUTHENTICATED_AT.minusSeconds(1));
		assertRejected("password", "revoked", 0, 0, 0, AUTHENTICATED_AT, AUTHENTICATED_AT.plusSeconds(1),
				EXPIRES_AT, AUTHENTICATED_AT.plusSeconds(2));
		assertThat(sessionCount()).isZero();
	}

	@Test
	void storesAValidRevokedSession() {
		insertUser(DEFAULT_TENANT_ID, USER_ID);
		OffsetDateTime revokedAt = AUTHENTICATED_AT.plusSeconds(1);

		insertSession(DEFAULT_TENANT_ID, SESSION_ID, USER_ID, "password", "revoked", 0, 0, 1,
				AUTHENTICATED_AT, revokedAt, EXPIRES_AT, revokedAt);

		assertThat(this.jdbcClient.sql("""
				SELECT status = 'revoked' AND version = 1 AND revoked_at = updated_at
				FROM user_sessions
				WHERE tenant_id = :tenantId AND session_id = :sessionId
				""")
			.param("tenantId", DEFAULT_TENANT_ID)
			.param("sessionId", SESSION_ID)
			.query(Boolean.class)
			.single()).isTrue();
	}

	@Test
	void preventsHardDeletionWhileASessionExists() {
		insertUser(DEFAULT_TENANT_ID, USER_ID);
		insertSession(DEFAULT_TENANT_ID, SESSION_ID, USER_ID, 0, 0);

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(sessionCount()).isOne();
	}

	private void assertRejected(String authenticationMethod, String status, long issuedTenantVersion,
			long issuedUserVersion, long version, OffsetDateTime authenticatedAt, OffsetDateTime updatedAt,
			OffsetDateTime expiresAt, OffsetDateTime revokedAt) {
		assertThatThrownBy(() -> insertSession(DEFAULT_TENANT_ID, SESSION_ID, USER_ID, authenticationMethod, status,
				issuedTenantVersion, issuedUserVersion, version, authenticatedAt, updatedAt, expiresAt, revokedAt))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name, version)
				VALUES (:tenantId, 'session-schema', 'Session Schema', 5)
				""").param("tenantId", SECOND_TENANT_ID).update();
	}

	private void insertUser(UUID tenantId, UUID userId) {
		insertUser(tenantId, userId, 0);
	}

	private void insertUser(UUID tenantId, UUID userId, long version) {
		this.jdbcClient.sql("""
				INSERT INTO users (tenant_id, user_id, version, security_version)
				VALUES (:tenantId, :userId, :version, :version)
				""")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.param("version", version)
			.update();
	}

	private void insertSession(UUID tenantId, UUID sessionId, UUID userId, long issuedTenantVersion,
			long issuedUserVersion) {
		insertSession(tenantId, sessionId, userId, "password", "active", issuedTenantVersion, issuedUserVersion, 0,
				AUTHENTICATED_AT, AUTHENTICATED_AT, EXPIRES_AT, null);
	}

	private void insertSession(UUID tenantId, UUID sessionId, UUID userId, String authenticationMethod, String status,
			long issuedTenantVersion, long issuedUserVersion, long version, OffsetDateTime authenticatedAt,
			OffsetDateTime updatedAt, OffsetDateTime expiresAt, OffsetDateTime revokedAt) {
		this.jdbcClient.sql("""
				INSERT INTO user_sessions
				    (tenant_id, session_id, user_id, authentication_method, status,
				     issued_tenant_version, issued_user_version, version,
				     authenticated_at, updated_at, expires_at, revoked_at)
				VALUES
				    (:tenantId, :sessionId, :userId, :authenticationMethod, :status,
				     :issuedTenantVersion, :issuedUserVersion, :version,
				     :authenticatedAt, :updatedAt, :expiresAt, :revokedAt)
				""")
			.param("tenantId", tenantId)
			.param("sessionId", sessionId)
			.param("userId", userId)
			.param("authenticationMethod", authenticationMethod)
			.param("status", status)
			.param("issuedTenantVersion", issuedTenantVersion)
			.param("issuedUserVersion", issuedUserVersion)
			.param("version", version)
			.param("authenticatedAt", authenticatedAt)
			.param("updatedAt", updatedAt)
			.param("expiresAt", expiresAt)
			.param("revokedAt", revokedAt)
			.update();
	}

	private int sessionCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_sessions
				WHERE session_id IN (:sessionId, :secondSessionId)
				""")
			.param("sessionId", SESSION_ID)
			.param("secondSessionId", SECOND_SESSION_ID)
			.query(Integer.class)
			.single();
	}

}
