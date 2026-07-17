package com.ixayda.iam.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class SessionOperationsIntegrationTests extends ApplicationIntegrationTest {

	private static final SessionAbsoluteTtl EIGHT_HOURS = new SessionAbsoluteTtl(Duration.ofHours(8));

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private SessionOperations sessions;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("""
					DELETE FROM user_login_identifiers
					WHERE tenant_id = :tenantId AND user_id = :userId
					""")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
		});
		this.tenantsToDelete.reversed().forEach(tenantId -> this.jdbcClient
			.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void startsAStoredSessionWithCurrentLifecycleVersionsAndFixedExpiration() {
		User user = createUser(TenantId.DEFAULT, "start");
		Tenant tenant = this.tenants.findById(TenantId.DEFAULT).orElseThrow();

		UserSession started = start(TenantId.DEFAULT, user.id(), EIGHT_HOURS);

		assertThat(started.issuedTenantVersion()).isEqualTo(tenant.version());
		assertThat(started.issuedUserVersion()).isEqualTo(user.securityVersion());
		assertThat(Duration.between(started.authenticatedAt(), started.expiresAt()))
			.isEqualTo(EIGHT_HOURS.value());
		assertThat(this.sessions.findById(TenantId.DEFAULT, started.id())).contains(started);
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, started.id())).contains(started);
	}

	@Test
	void requiresTheCallerTransactionAndParticipatesInRollback() {
		User user = createUser(TenantId.DEFAULT, "transaction");

		assertThatThrownBy(() -> this.sessions.start(TenantId.DEFAULT, user.id(),
				SessionAuthenticationMethod.PASSWORD, EIGHT_HOURS))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.sessions.start(TenantId.DEFAULT, user.id(),
				SessionAuthenticationMethod.PASSWORD, EIGHT_HOURS)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Starting a session requires an existing read-write transaction");

		AtomicReference<UserSession> rolledBack = new AtomicReference<>();
		transactionTemplate().executeWithoutResult(status -> {
			rolledBack.set(this.sessions.start(TenantId.DEFAULT, user.id(),
					SessionAuthenticationMethod.PASSWORD, EIGHT_HOURS));
			status.setRollbackOnly();
		});
		assertThat(this.sessions.findById(TenantId.DEFAULT, rolledBack.get().id())).isEmpty();
	}

	@Test
	void doesNotStartASessionForAnInactiveUser() {
		User user = createUser(TenantId.DEFAULT, "inactive");
		this.users.disable(TenantId.DEFAULT, user.id());

		assertThatThrownBy(() -> start(TenantId.DEFAULT, user.id(), EIGHT_HOURS))
			.isInstanceOf(UserNotActiveException.class);
		assertThat(sessionCount(TenantId.DEFAULT, user.id())).isZero();
	}

	@Test
	void userReactivationDoesNotRestoreAnOldSession() {
		User user = createUser(TenantId.DEFAULT, "user-version");
		UserSession started = start(TenantId.DEFAULT, user.id(), EIGHT_HOURS);

		this.users.disable(TenantId.DEFAULT, user.id());
		User reactivated = this.users.activate(TenantId.DEFAULT, user.id());

		assertThat(reactivated.isActive()).isTrue();
		assertThat(reactivated.securityVersion()).isGreaterThan(started.issuedUserVersion());
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, started.id())).isEmpty();
		assertThat(this.sessions.findById(TenantId.DEFAULT, started.id())).contains(started);
	}

	@Test
	void profileUpdatesDoNotInvalidateAnActiveSession() {
		User user = createUser(TenantId.DEFAULT, "profile-version");
		UserSession started = start(TenantId.DEFAULT, user.id(), EIGHT_HOURS);

		User updated = this.users.updateProfile(TenantId.DEFAULT, user.id(), user.version(),
				new UserProfile("Alice Example", "Alice Q. Example", "Alice", "Example"));

		assertThat(updated.version()).isGreaterThan(user.version());
		assertThat(updated.securityVersion()).isEqualTo(user.securityVersion());
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, started.id())).contains(started);

		UserSession startedAfterUpdate = start(TenantId.DEFAULT, user.id(), EIGHT_HOURS);
		assertThat(startedAfterUpdate.issuedUserVersion()).isEqualTo(updated.securityVersion());
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, startedAfterUpdate.id())).contains(startedAfterUpdate);
	}

	@Test
	void tenantReactivationDoesNotRestoreAnOldSession() {
		Tenant tenant = createTenant("tenant-version");
		User user = createUser(tenant.id(), "tenant-version");
		UserSession started = start(tenant.id(), user.id(), EIGHT_HOURS);

		this.tenants.disable(tenant.id());
		Tenant reactivated = this.tenants.activate(tenant.id());

		assertThat(reactivated.isActive()).isTrue();
		assertThat(reactivated.version()).isGreaterThan(started.issuedTenantVersion());
		assertThat(this.sessions.findUsable(tenant.id(), started.id())).isEmpty();
		assertThat(this.sessions.findById(tenant.id(), started.id())).contains(started);
	}

	@Test
	void revokesWithinTheTenantAndConvergesIdempotently() {
		User user = createUser(TenantId.DEFAULT, "revoke");
		UserSession started = start(TenantId.DEFAULT, user.id(), EIGHT_HOURS);
		TenantId otherTenant = TenantId.random();

		assertThatThrownBy(() -> this.sessions.revoke(otherTenant, started.id()))
			.isInstanceOf(UserSessionNotFoundException.class)
			.extracting("tenantId", "sessionId")
			.containsExactly(otherTenant, started.id());

		UserSession revoked = this.sessions.revoke(TenantId.DEFAULT, started.id());
		UserSession repeated = this.sessions.revoke(TenantId.DEFAULT, started.id());

		assertThat(revoked.isRevoked()).isTrue();
		assertThat(revoked.version()).isOne();
		assertThat(repeated).isEqualTo(revoked);
		assertThat(this.sessions.findById(TenantId.DEFAULT, started.id())).contains(revoked);
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, started.id())).isEmpty();
	}

	@Test
	void revocationParticipatesInTheCallerRollback() {
		User user = createUser(TenantId.DEFAULT, "revoke-rollback");
		UserSession started = start(TenantId.DEFAULT, user.id(), EIGHT_HOURS);

		transactionTemplate().executeWithoutResult(status -> {
			this.sessions.revoke(TenantId.DEFAULT, started.id());
			status.setRollbackOnly();
		});

		assertThat(this.sessions.findById(TenantId.DEFAULT, started.id())).contains(started);
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, started.id())).contains(started);
	}

	private UserSession start(TenantId tenantId, UserId userId, SessionAbsoluteTtl ttl) {
		return transactionTemplate().execute(status -> this.sessions.start(tenantId, userId,
				SessionAuthenticationMethod.PASSWORD, ttl));
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username("session-" + purpose + "-" + suffix))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		return user;
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("session-" + suffix, "Session " + purpose));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private int sessionCount(TenantId tenantId, UserId userId) {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_sessions
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query(Integer.class)
			.single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
