package com.ixayda.iam.session.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionStatus;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcUserSessionRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e41"));

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e42");

	private static final UserId SECOND_USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e43");

	private static final UserId SAME_TENANT_USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e46");

	private static final SessionId SESSION_ID =
			SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e44");

	private static final SessionId SECOND_SESSION_ID =
			SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e45");

	private static final Instant AUTHENTICATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final Instant EXPIRES_AT = AUTHENTICATED_AT.plusSeconds(8 * 60 * 60);

	@Autowired
	private JdbcUserSessionRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createUsers() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name, version)
				VALUES (:tenantId, 'session-store-tenant', 'Session Store Tenant', 5)
				""").param("tenantId", SECOND_TENANT_ID.value()).update();
		insertUser(TenantId.DEFAULT, USER_ID, 7);
		insertUser(TenantId.DEFAULT, SAME_TENANT_USER_ID, 7);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID, 11);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE session_id IN (:sessionId, :secondSessionId)")
			.param("sessionId", SESSION_ID.value())
			.param("secondSessionId", SECOND_SESSION_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:userId, :sameTenantUserId, :secondUserId)")
			.param("userId", USER_ID.value())
			.param("sameTenantUserId", SAME_TENANT_USER_ID.value())
			.param("secondUserId", SECOND_USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void storesAndFindsTenantScopedSessions() {
		UserSession first = session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7);
		UserSession second = session(SECOND_SESSION_ID, SECOND_TENANT_ID, SECOND_USER_ID, 5, 11);

		assertThat(insert(first)).isSameAs(first);
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(first);
		assertThat(this.repository.findById(SECOND_TENANT_ID, SESSION_ID)).isEmpty();

		insert(second);
		assertThat(this.repository.findById(SECOND_TENANT_ID, SECOND_SESSION_ID)).contains(second);
	}

	@Test
	void rejectsGlobalSessionIdDuplicatesWithoutAbortingTheCallerTransaction() {
		UserSession first = session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7);
		UserSession duplicate = session(SESSION_ID, SECOND_TENANT_ID, SECOND_USER_ID, 5, 11);

		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(first);
			assertThatThrownBy(() -> this.repository.insert(duplicate))
				.isInstanceOf(UserSessionAlreadyExistsException.class)
				.extracting("tenantId", "sessionId")
				.containsExactly(SECOND_TENANT_ID, SESSION_ID);
			assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(first);
		});

		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(first);
	}

	@Test
	void revokesUsingTenantScopedOptimisticLocking() {
		UserSession current = insert(session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7));
		UserSession revoked = current.revoke(AUTHENTICATED_AT.plusSeconds(60));

		assertThat(update(current, revoked)).isSameAs(revoked);
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(revoked);
		assertThatThrownBy(() -> update(current, revoked))
			.isInstanceOf(UserSessionConcurrentUpdateException.class)
			.extracting("tenantId", "sessionId", "expectedVersion")
			.containsExactly(TenantId.DEFAULT, SESSION_ID, 0L);
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(revoked);
	}

	@Test
	void doesNotRevokeASessionThroughAnotherTenant() {
		UserSession stored = insert(session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7));
		UserSession forgedCurrent = session(SESSION_ID, SECOND_TENANT_ID, SECOND_USER_ID, 5, 11);
		UserSession forgedRevocation = forgedCurrent.revoke(AUTHENTICATED_AT.plusSeconds(60));

		assertThatThrownBy(() -> update(forgedCurrent, forgedRevocation))
			.isInstanceOf(UserSessionConcurrentUpdateException.class);
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(stored);
	}

	@Test
	void doesNotRevokeAnotherUsersSessionInTheSameTenant() {
		UserSession stored = insert(session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7));
		UserSession forgedCurrent = session(SESSION_ID, TenantId.DEFAULT, SAME_TENANT_USER_ID, 0, 7);
		UserSession forgedRevocation = forgedCurrent.revoke(AUTHENTICATED_AT.plusSeconds(60));

		assertThatThrownBy(() -> update(forgedCurrent, forgedRevocation))
			.isInstanceOf(UserSessionConcurrentUpdateException.class);
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(stored);
	}

	@Test
	void keepsTheCallerTransactionUsableAfterAConcurrentUpdate() {
		UserSession current = insert(session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7));
		UserSession winner = current.revoke(AUTHENTICATED_AT.plusSeconds(60));
		update(current, winner);

		UserSession latest = transactionTemplate().execute(status -> {
			assertThatThrownBy(() -> this.repository.update(current, winner))
				.isInstanceOf(UserSessionConcurrentUpdateException.class);
			return this.repository.findById(TenantId.DEFAULT, SESSION_ID).orElseThrow();
		});

		assertThat(latest).isEqualTo(winner);
	}

	@Test
	void participatesInCallerRollback() {
		UserSession initial = session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7);
		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(initial);
			status.setRollbackOnly();
		});
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).isEmpty();

		insert(initial);
		UserSession revoked = initial.revoke(AUTHENTICATED_AT.plusSeconds(60));
		transactionTemplate().executeWithoutResult(status -> {
			this.repository.update(initial, revoked);
			status.setRollbackOnly();
		});
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(initial);
	}

	@Test
	void requiresAnExistingReadWriteTransaction() {
		UserSession initial = session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7);

		assertThatThrownBy(() -> this.repository.insert(initial))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.insert(initial)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("User session write requires an existing read-write transaction");

		insert(initial);
		UserSession revoked = initial.revoke(AUTHENTICATED_AT.plusSeconds(60));
		assertThatThrownBy(() -> this.repository.update(initial, revoked))
			.isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.update(initial, revoked)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("User session write requires an existing read-write transaction");
		assertThat(this.repository.findById(TenantId.DEFAULT, SESSION_ID)).contains(initial);
	}

	@Test
	void rejectsChangesToIssuanceState() {
		UserSession current = session(SESSION_ID, TenantId.DEFAULT, USER_ID, 0, 7);
		Instant revokedAt = AUTHENTICATED_AT.plusSeconds(60);
		UserSession changedUser = new UserSession(current.id(), current.tenantId(), SECOND_USER_ID,
				current.authenticationMethod(), SessionStatus.REVOKED, current.issuedTenantVersion(),
				current.issuedUserVersion(), 1, current.authenticatedAt(), revokedAt, current.expiresAt(), revokedAt);
		UserSession changedExpiry = new UserSession(current.id(), current.tenantId(), current.userId(),
				current.authenticationMethod(), SessionStatus.REVOKED, current.issuedTenantVersion(),
				current.issuedUserVersion(), 1, current.authenticatedAt(), revokedAt,
				current.expiresAt().plusSeconds(1), revokedAt);
		UserSession skippedVersion = new UserSession(current.id(), current.tenantId(), current.userId(),
				current.authenticationMethod(), SessionStatus.REVOKED, current.issuedTenantVersion(),
				current.issuedUserVersion(), 2, current.authenticatedAt(), revokedAt, current.expiresAt(), revokedAt);

		assertThatThrownBy(() -> update(current, changedUser)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedExpiry)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, skippedVersion)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, current)).isInstanceOf(IllegalArgumentException.class);
	}

	private UserSession session(SessionId sessionId, TenantId tenantId, UserId userId, long tenantVersion,
			long userVersion) {
		return UserSession.start(sessionId, tenantId, userId, SessionAuthenticationMethod.PASSWORD, tenantVersion,
				userVersion, AUTHENTICATED_AT, EXPIRES_AT);
	}

	private UserSession insert(UserSession session) {
		return transactionTemplate().execute(status -> this.repository.insert(session));
	}

	private UserSession update(UserSession current, UserSession changed) {
		return transactionTemplate().execute(status -> this.repository.update(current, changed));
	}

	private void insertUser(TenantId tenantId, UserId userId, long version) {
		this.jdbcClient
			.sql("""
					INSERT INTO users (tenant_id, user_id, version, security_version)
					VALUES (:tenantId, :userId, :version, :version)
					""")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("version", version)
			.update();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

}
