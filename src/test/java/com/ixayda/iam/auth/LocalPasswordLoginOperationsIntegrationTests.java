package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class LocalPasswordLoginOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private LocalPasswordLoginOperations logins;

	@Autowired
	private PasswordOperations passwords;

	@Autowired
	private SessionOperations sessions;

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
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
	void authenticatesAndPersistsAFixedLifetimeSessionAtomically() {
		User user = createUser(TenantId.DEFAULT, "success");
		setPassword(user, "correct-password");

		LocalPasswordLoginResult result = login(TenantId.DEFAULT, loginKey(user), "correct-password");

		assertThat(result.authenticated()).isTrue();
		UserSession session = result.session().orElseThrow();
		assertThat(session.userId()).isEqualTo(user.id());
		assertThat(Duration.between(session.authenticatedAt(), session.expiresAt()))
			.isEqualTo(Duration.ofHours(8));
		assertThat(this.sessions.findById(TenantId.DEFAULT, session.id())).contains(session);
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, session.id())).contains(session);
		assertThat(sessionCount(TenantId.DEFAULT, user.id())).isOne();
	}

	@Test
	void returnsOneGenericFailureForAllCredentialAndUserFailures() {
		User inactive = createUser(TenantId.DEFAULT, "inactive");
		setPassword(inactive, "correct-password");
		this.users.disable(TenantId.DEFAULT, inactive.id());
		User withoutCredential = createUser(TenantId.DEFAULT, "no-credential");
		User wrongPassword = createUser(TenantId.DEFAULT, "wrong-password");
		setPassword(wrongPassword, "correct-password");
		LoginKey unknown = LoginKey.from("unknown-" + UUID.randomUUID().toString().substring(0, 8));

		LocalPasswordLoginResult unknownResult = login(TenantId.DEFAULT, unknown, "candidate-password");
		LocalPasswordLoginResult inactiveResult = login(TenantId.DEFAULT, loginKey(inactive), "correct-password");
		LocalPasswordLoginResult missingResult =
				login(TenantId.DEFAULT, loginKey(withoutCredential), "candidate-password");
		LocalPasswordLoginResult mismatchResult =
				login(TenantId.DEFAULT, loginKey(wrongPassword), "wrong-password");

		assertThat(unknownResult).isSameAs(LocalPasswordLoginResult.failure());
		assertThat(inactiveResult).isSameAs(unknownResult);
		assertThat(missingResult).isSameAs(unknownResult);
		assertThat(mismatchResult).isSameAs(unknownResult);
		assertThat(sessionCount(TenantId.DEFAULT, inactive.id())).isZero();
		assertThat(sessionCount(TenantId.DEFAULT, withoutCredential.id())).isZero();
		assertThat(sessionCount(TenantId.DEFAULT, wrongPassword.id())).isZero();
	}

	@Test
	void returnsFailureWithoutPoisoningTheTransactionForADisabledTenant() {
		Tenant tenant = createTenant();
		User user = createUser(tenant.id(), "disabled-tenant");
		setPassword(user, "correct-password");
		this.tenants.disable(tenant.id());

		LocalPasswordLoginResult result = login(tenant.id(), loginKey(user), "correct-password");

		assertThat(result).isSameAs(LocalPasswordLoginResult.failure());
		assertThat(sessionCount(tenant.id(), user.id())).isZero();
	}

	private LocalPasswordLoginResult login(TenantId tenantId, LoginKey loginKey, String password) {
		try (PasswordAttempt attempt = new PasswordAttempt(password.toCharArray())) {
			return this.logins.login(tenantId, loginKey, attempt);
		}
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username("auth-" + purpose + "-" + suffix))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		return user;
	}

	private Tenant createTenant() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("auth-" + suffix, "Auth Tenant"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private void setPassword(User user, String password) {
		try (NewPassword newPassword = new NewPassword(password.toCharArray())) {
			this.passwords.setPassword(user.tenantId(), user.id(), newPassword);
		}
	}

	private LoginKey loginKey(User user) {
		return user.identifiers().getFirst().loginKey();
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

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
