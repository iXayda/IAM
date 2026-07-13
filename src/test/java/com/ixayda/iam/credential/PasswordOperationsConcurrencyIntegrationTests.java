package com.ixayda.iam.credential;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class PasswordOperationsConcurrencyIntegrationTests extends ApplicationIntegrationTest {

	private final List<UserId> usersToDelete = new ArrayList<>();

	@Autowired
	private PasswordOperations passwords;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(userId -> {
			this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("userId", userId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("userId", userId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("userId", userId.value())
				.update();
		});
	}

	@Test
	void serializesConcurrentInitialPasswordWrites() throws Exception {
		User user = createUser("concurrent-set");
		CountDownLatch firstStored = new CountDownLatch(1);
		CountDownLatch releaseFirst = new CountDownLatch(1);
		CountDownLatch secondStarted = new CountDownLatch(1);
		AtomicInteger secondBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Void> first = executor.submit(() -> {
				transactionTemplate().executeWithoutResult(status -> {
					setPassword(user, "first-password");
					firstStored.countDown();
					await(releaseFirst, "Timed out holding the first password write");
				});
				return null;
			});
			Future<Void> second;
			try {
				assertThat(firstStored.await(5, TimeUnit.SECONDS)).isTrue();
				second = executor.submit(() -> {
					transactionTemplate().executeWithoutResult(status -> {
						secondBackendId.set(backendId());
						secondStarted.countDown();
						setPassword(user, "second-password");
					});
					return null;
				});
				assertThat(secondStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(secondBackendId.get())).isTrue();
			}
			finally {
				releaseFirst.countDown();
			}

			first.get(5, TimeUnit.SECONDS);
			second.get(5, TimeUnit.SECONDS);
		}

		assertThat(credentialCount(user)).isEqualTo(1);
		assertThat(credentialVersion(user)).isEqualTo(1);
		assertThat(verify(user, "first-password")).isFalse();
		assertThat(verify(user, "second-password")).isTrue();
	}

	@Test
	void rejectsAnOldAttemptWhenAConcurrentPasswordChangeCommits() throws Exception {
		User user = createUser("change-during-verify");
		setPassword(user, "old-password");
		CountDownLatch changeStored = new CountDownLatch(1);
		CountDownLatch releaseChange = new CountDownLatch(1);
		CountDownLatch verificationStarted = new CountDownLatch(1);
		AtomicInteger verificationBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Void> change = executor.submit(() -> {
				transactionTemplate().executeWithoutResult(status -> {
					setPassword(user, "new-password");
					changeStored.countDown();
					await(releaseChange, "Timed out holding the password change");
				});
				return null;
			});
			Future<Boolean> verification;
			try {
				assertThat(changeStored.await(5, TimeUnit.SECONDS)).isTrue();
				verification = executor.submit(() -> transactionTemplate().execute(status -> {
					verificationBackendId.set(backendId());
					verificationStarted.countDown();
					return verifyInCurrentTransaction(user, "old-password");
				}));
				assertThat(verificationStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(verificationBackendId.get())).isTrue();
			}
			finally {
				releaseChange.countDown();
			}

			change.get(5, TimeUnit.SECONDS);
			assertThat(verification.get(5, TimeUnit.SECONDS)).isFalse();
		}

		assertThat(verify(user, "new-password")).isTrue();
	}

	@Test
	void holdsTheUserGuardUntilTheAuthenticationTransactionCommits() throws Exception {
		User user = createUser("guard-duration");
		setPassword(user, "correct-password");
		CountDownLatch passwordVerified = new CountDownLatch(1);
		CountDownLatch releaseVerification = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Boolean> verification = executor.submit(() -> transactionTemplate().execute(status -> {
				boolean matched = verifyInCurrentTransaction(user, "correct-password");
				passwordVerified.countDown();
				await(releaseVerification, "Timed out holding the authentication transaction");
				return matched;
			}));
			Future<User> disable;
			try {
				assertThat(passwordVerified.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.users.disable(TenantId.DEFAULT, user.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(disableBackendId.get())).isTrue();
			}
			finally {
				releaseVerification.countDown();
			}

			assertThat(verification.get(5, TimeUnit.SECONDS)).isTrue();
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
		}
	}

	private User createUser(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("password-" + purpose + "-" + suffix))));
		this.usersToDelete.add(user.id());
		return user;
	}

	private void setPassword(User user, String value) {
		try (NewPassword password = new NewPassword(value.toCharArray())) {
			this.passwords.setPassword(TenantId.DEFAULT, user.id(), password);
		}
	}

	private boolean verify(User user, String value) {
		return Boolean.TRUE.equals(transactionTemplate()
			.execute(status -> verifyInCurrentTransaction(user, value)));
	}

	private boolean verifyInCurrentTransaction(User user, String value) {
		try (PasswordAttempt attempt = new PasswordAttempt(value.toCharArray())) {
			return this.passwords.verifyPassword(TenantId.DEFAULT, user.id(), attempt);
		}
	}

	private long credentialCount(User user) {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_password_credentials
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", user.id().value())
			.query(Long.class)
			.single();
	}

	private long credentialVersion(User user) {
		return this.jdbcClient.sql("""
				SELECT version
				FROM user_password_credentials
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", user.id().value())
			.query(Long.class)
			.single();
	}

	private int backendId() {
		return this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private boolean waitUntilBlocked(int backendId) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		do {
			boolean blocked = this.jdbcClient.sql("SELECT cardinality(pg_blocking_pids(:backendId)) > 0")
				.param("backendId", backendId)
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
			throw new IllegalStateException("Interrupted while coordinating password operations", ex);
		}
	}

}
