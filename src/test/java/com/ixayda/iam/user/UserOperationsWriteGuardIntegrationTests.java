package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class UserOperationsWriteGuardIntegrationTests extends ApplicationIntegrationTest {

	private final List<UserId> usersToDelete = new ArrayList<>();

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(userId -> {
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
	void preventsUserDisableUntilTheGuardedWriteCommits() throws Exception {
		User user = createUser("guard-first");
		CountDownLatch guardAcquired = new CountDownLatch(1);
		CountDownLatch releaseGuard = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<User> guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				User active = this.users.requireActiveForWrite(TenantId.DEFAULT, user.id());
				guardAcquired.countDown();
				await(releaseGuard, "Timed out holding the user write guard");
				return active;
			}));
			Future<User> disable;
			try {
				assertThat(guardAcquired.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.users.disable(TenantId.DEFAULT, user.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(disableBackendId.get())).isTrue();
			}
			finally {
				releaseGuard.countDown();
			}

			assertThat(guardedWrite.get(5, TimeUnit.SECONDS)).isEqualTo(user);
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
		}
	}

	@Test
	void rejectsTheGuardedWriteWhenUserDisableCommitsFirst() throws Exception {
		User user = createUser("disable-first");
		CountDownLatch userDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch guardStarted = new CountDownLatch(1);
		AtomicInteger guardBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<User> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				User disabled = this.users.disable(TenantId.DEFAULT, user.id());
				userDisabled.countDown();
				await(releaseDisable, "Timed out holding the user disable transaction");
				return disabled;
			}));
			Future<User> guardedWrite;
			try {
				assertThat(userDisabled.await(5, TimeUnit.SECONDS)).isTrue();
				guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
					guardBackendId.set(backendId());
					guardStarted.countDown();
					return this.users.requireActiveForWrite(TenantId.DEFAULT, user.id());
				}));
				assertThat(guardStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(guardBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
			assertThatThrownBy(() -> guardedWrite.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(UserNotActiveException.class);
		}

		assertThat(this.users.findById(TenantId.DEFAULT, user.id()))
			.get()
			.extracting(User::status)
			.isEqualTo(UserStatus.DISABLED);
	}

	private User createUser(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("write-guard-" + purpose + "-" + suffix))));
		this.usersToDelete.add(user.id());
		return user;
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
			throw new IllegalStateException("Interrupted while coordinating user writes", ex);
		}
	}

}
