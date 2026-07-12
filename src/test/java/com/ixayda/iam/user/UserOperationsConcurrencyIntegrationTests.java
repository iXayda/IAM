package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class UserOperationsConcurrencyIntegrationTests extends ApplicationIntegrationTest {

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.forEach(tenantId -> {
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
		});
	}

	@Test
	void convergesConcurrentUpdatesToTheSameStatus() throws Exception {
		User created = createUser("same-target");

		List<UpdateResult> results = race(created, this.users::disable, this.users::disable);

		User stored = this.users.findById(created.tenantId(), created.id()).orElseThrow();
		assertThat(results).allSatisfy(result -> {
			assertThat(result.failure()).isNull();
			assertThat(result.user()).isEqualTo(stored);
			assertThat(this.users.findById(created.tenantId(), result.markerId())).isPresent();
		});
		assertThat(stored.status()).isEqualTo(UserStatus.DISABLED);
		assertThat(stored.version()).isOne();
	}

	@Test
	void preservesAConflictForConcurrentUpdatesToDifferentStatuses() throws Exception {
		User created = createUser("different-targets");

		List<UpdateResult> results = race(created, this.users::disable, this.users::lock);

		List<User> successes = results.stream().map(UpdateResult::user).filter(Objects::nonNull).toList();
		List<RuntimeException> failures =
				results.stream().map(UpdateResult::failure).filter(Objects::nonNull).toList();
		assertThat(successes).hasSize(1);
		assertThat(failures).singleElement().isInstanceOf(UserConcurrentUpdateException.class);
		UserConcurrentUpdateException conflict = (UserConcurrentUpdateException) failures.getFirst();
		assertThat(conflict.tenantId()).isEqualTo(created.tenantId());
		assertThat(conflict.userId()).isEqualTo(created.id());
		assertThat(conflict.expectedVersion()).isZero();

		User stored = this.users.findById(created.tenantId(), created.id()).orElseThrow();
		assertThat(stored).isEqualTo(successes.getFirst());
		assertThat(stored.status()).isIn(UserStatus.DISABLED, UserStatus.LOCKED);
		assertThat(stored.version()).isOne();
		UpdateResult success = results.stream().filter(result -> result.failure() == null).findFirst().orElseThrow();
		UpdateResult failure = results.stream().filter(result -> result.failure() != null).findFirst().orElseThrow();
		assertThat(this.users.findById(created.tenantId(), success.markerId())).isPresent();
		assertThat(this.users.findById(created.tenantId(), failure.markerId())).isEmpty();
	}

	private List<UpdateResult> race(User user, StatusCommand firstCommand, StatusCommand secondCommand)
			throws Exception {
		CountDownLatch rowLocked = new CountDownLatch(1);
		CountDownLatch releaseRow = new CountDownLatch(1);
		CountDownLatch workersStarted = new CountDownLatch(2);
		AtomicInteger firstBackendId = new AtomicInteger();
		AtomicInteger secondBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(3)) {
			Future<?> locker = executor.submit(() -> transactionTemplate().executeWithoutResult(status -> {
				this.jdbcClient.sql("""
						SELECT user_id FROM users
						WHERE tenant_id = :tenantId AND user_id = :userId
						FOR UPDATE
						""")
					.param("tenantId", user.tenantId().value())
					.param("userId", user.id().value())
					.query(UUID.class)
					.single();
				rowLocked.countDown();
				await(releaseRow, "Timed out holding the user row lock");
			}));

			Future<UpdateResult> first;
			Future<UpdateResult> second;
			try {
				assertThat(rowLocked.await(5, TimeUnit.SECONDS)).isTrue();
				first = executor.submit(() -> update(user, firstCommand, firstBackendId, workersStarted));
				second = executor.submit(() -> update(user, secondCommand, secondBackendId, workersStarted));
				assertThat(workersStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(firstBackendId.get())).isTrue();
				assertThat(waitUntilBlocked(secondBackendId.get())).isTrue();
			}
			finally {
				releaseRow.countDown();
			}

			locker.get(5, TimeUnit.SECONDS);
			return List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
		}
	}

	private UpdateResult update(User user, StatusCommand command, AtomicInteger backendId,
			CountDownLatch workersStarted) {
		AtomicReference<UserId> markerId = new AtomicReference<>();
		try {
			User updated = transactionTemplate().execute(status -> {
				backendId.set(this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single());
				workersStarted.countDown();
				User marker = this.users.create(user.tenantId(), new CreateUserRequest(
						List.of(LoginIdentifier.username("marker-" + UUID.randomUUID()))));
				markerId.set(marker.id());
				return command.execute(user.tenantId(), user.id());
			});
			return new UpdateResult(updated, null, markerId.get());
		}
		catch (RuntimeException ex) {
			return new UpdateResult(null, ex, markerId.get());
		}
	}

	private User createUser(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants
			.create(new CreateTenantRequest("user-concurrency-" + suffix, "User Concurrency Test"));
		this.tenantsToDelete.add(tenant.id());
		return this.users.create(tenant.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username(purpose + "-" + suffix))));
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
			throw new IllegalStateException("Interrupted while coordinating a user update", ex);
		}
	}

	@FunctionalInterface
	private interface StatusCommand {

		User execute(TenantId tenantId, UserId userId);

	}

	private record UpdateResult(User user, RuntimeException failure, UserId markerId) {
	}

}
