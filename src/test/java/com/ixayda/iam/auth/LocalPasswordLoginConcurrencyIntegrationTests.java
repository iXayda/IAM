package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class LocalPasswordLoginConcurrencyIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private LocalPasswordLoginOperations logins;

	@Autowired
	private PasswordOperations passwords;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

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
	void commitsASuccessfulLoginBeforeAConcurrentUserDisable() throws Exception {
		this.user = createUser("login-first");
		setPassword("correct-password");
		CountDownLatch sessionStarted = new CountDownLatch(1);
		CountDownLatch releaseLogin = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger loginBackendId = new AtomicInteger();
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<LocalPasswordLoginResult> login = executor.submit(() -> transactionTemplate().execute(status -> {
				loginBackendId.set(backendId());
				LocalPasswordLoginResult result = loginInCurrentTransaction("correct-password");
				sessionStarted.countDown();
				await(releaseLogin, "Timed out holding the successful login transaction");
				return result;
			}));
			Future<User> disable;
			try {
				assertThat(sessionStarted.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.users.disable(TenantId.DEFAULT, this.user.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(disableBackendId.get(), loginBackendId.get())).isTrue();
			}
			finally {
				releaseLogin.countDown();
			}

			LocalPasswordLoginResult result = login.get(5, TimeUnit.SECONDS);
			assertThat(result.authenticated()).isTrue();
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
		}

		assertThat(sessionCount()).isOne();
		assertThat(this.users.findById(TenantId.DEFAULT, this.user.id()).orElseThrow().status())
			.isEqualTo(UserStatus.DISABLED);
	}

	@Test
	void returnsGenericFailureWhenAConcurrentUserDisableCommitsFirst() throws Exception {
		this.user = createUser("disable-first");
		setPassword("correct-password");
		CountDownLatch userDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch loginStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();
		AtomicInteger loginBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<User> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				disableBackendId.set(backendId());
				User disabled = this.users.disable(TenantId.DEFAULT, this.user.id());
				userDisabled.countDown();
				await(releaseDisable, "Timed out holding the user disable transaction");
				return disabled;
			}));
			Future<LocalPasswordLoginResult> login;
			try {
				assertThat(userDisabled.await(5, TimeUnit.SECONDS)).isTrue();
				login = executor.submit(() -> transactionTemplate().execute(status -> {
					loginBackendId.set(backendId());
					loginStarted.countDown();
					return loginInCurrentTransaction("correct-password");
				}));
				assertThat(loginStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(loginBackendId.get(), disableBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
			assertThat(login.get(5, TimeUnit.SECONDS)).isSameAs(LocalPasswordLoginResult.failure());
		}

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

	private LocalPasswordLoginResult loginInCurrentTransaction(String value) {
		try (PasswordAttempt attempt = new PasswordAttempt(value.toCharArray())) {
			return this.logins.login(TenantId.DEFAULT, loginKey(), attempt);
		}
	}

	private LoginKey loginKey() {
		return this.user.identifiers().getFirst().loginKey();
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

	private int backendId() {
		return this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private boolean waitUntilBlockedBy(int backendId, int blockerBackendId) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		do {
			boolean blocked = this.jdbcClient.sql("SELECT :blockerBackendId = ANY(pg_blocking_pids(:backendId))")
				.param("backendId", backendId)
				.param("blockerBackendId", blockerBackendId)
				.query(Boolean.class)
				.single();
			if (blocked) {
				return true;
			}
			Thread.sleep(10);
		}
		while (System.nanoTime() < deadline);
		return false;
	}

	private static void await(CountDownLatch latch, String timeoutMessage) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException(timeoutMessage);
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while coordinating local password login", ex);
		}
	}

}
