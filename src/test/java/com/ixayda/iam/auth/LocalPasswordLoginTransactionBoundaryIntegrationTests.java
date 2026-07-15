package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.ratelimit.LoginAttemptDecision;
import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptLease;
import com.ixayda.iam.ratelimit.LoginAttemptLimiter;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class LocalPasswordLoginTransactionBoundaryIntegrationTests extends ApplicationIntegrationTest {

	private static final LoginAttemptLease LEASE =
			LoginAttemptLease.from("0123456789abcdefghijkl");

	@Autowired
	private LocalPasswordLoginOperations logins;

	@Autowired
	private PasswordOperations passwords;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@MockitoBean
	private LoginAttemptLimiter limiter;

	private User user;

	@AfterEach
	void deleteFixtures() {
		if (this.user == null) {
			return;
		}
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
	}

	@Test
	void acquiresOutsideTheTransactionAndResetsOnlyAfterTheSessionCommit() {
		this.user = createUser("boundaries");
		setPassword("correct-password");
		LoginAttemptSource source = trustedSource("boundaries");
		LoginAttemptKey attemptKey = new LoginAttemptKey(TenantId.DEFAULT, loginKey(), source);
		when(this.limiter.acquire(attemptKey)).thenAnswer(invocation -> {
			assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
			return LoginAttemptDecision.allowed(LEASE);
		});
		doAnswer(invocation -> {
			assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
			assertThat(sessionCount()).isOne();
			return null;
		}).when(this.limiter).recordSuccess(attemptKey, LEASE);

		LocalPasswordLoginResult result = login(source, "correct-password");

		assertThat(result.authenticated()).isTrue();
		assertThat(sessionCount()).isOne();
		verify(this.limiter).recordSuccess(attemptKey, LEASE);
	}

	@Test
	void doesNotCreateASessionWhenTheLimiterIsUnavailable() {
		this.user = createUser("unavailable");
		setPassword("correct-password");
		LoginAttemptSource source = trustedSource("unavailable");
		LoginAttemptKey attemptKey = new LoginAttemptKey(TenantId.DEFAULT, loginKey(), source);
		when(this.limiter.acquire(attemptKey)).thenReturn(LoginAttemptDecision.unavailable());

		LocalPasswordLoginResult result = login(source, "correct-password");

		assertThat(result).isSameAs(LocalPasswordLoginResult.unavailable());
		assertThat(sessionCount()).isZero();
	}

	private User createUser(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("auth-" + purpose + "-" + suffix))));
	}

	private void setPassword(String value) {
		try (NewPassword password = new NewPassword(value.toCharArray())) {
			this.passwords.setPassword(TenantId.DEFAULT, this.user.id(), password);
		}
	}

	private LocalPasswordLoginResult login(LoginAttemptSource source, String value) {
		try (PasswordAttempt attempt = new PasswordAttempt(value.toCharArray())) {
			return this.logins.login(TenantId.DEFAULT, loginKey(), source, attempt);
		}
	}

	private LoginKey loginKey() {
		return this.user.identifiers().getFirst().loginKey();
	}

	private LoginAttemptSource trustedSource(String purpose) {
		return LoginAttemptSource.trusted(purpose + "-" + UUID.randomUUID());
	}

	private int sessionCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_sessions
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.query(Integer.class)
			.single();
	}

}
