package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class UserExternalIdentityOperationsConcurrencyIntegrationTests extends ApplicationIntegrationTest {

	private static final ExternalIdentityProviderId PROVIDER_ID =
			ExternalIdentityProviderId.from("corporate");

	private static final ExternalSubjectId SUBJECT_ID = ExternalSubjectId.from("subject-a");

	private static final ExternalSubjectId SECOND_SUBJECT_ID = ExternalSubjectId.from("subject-b");

	@Autowired
	private UserExternalIdentityOperations identities;

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	private User firstUser;

	private User secondUser;

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@BeforeEach
	void createUsers() {
		this.firstUser = createUser("first");
		this.secondUser = createUser("second");
	}

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("""
					DELETE FROM user_external_identities
					WHERE tenant_id = :tenantId AND user_id = :userId
					""")
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
	void convergesConcurrentExactLinks() throws Exception {
		List<UserExternalIdentity> results = invokeConcurrently(8,
				() -> this.identities.link(TenantId.DEFAULT, this.firstUser.id(), PROVIDER_ID, SUBJECT_ID));

		UserExternalIdentity stored = stored(SUBJECT_ID);
		assertThat(results).allMatch(stored::equals);
		assertThat(identityCount()).isOne();
	}

	@Test
	void permitsOnlyOneOwnerForAConcurrentSubjectRace() throws Exception {
		List<LinkAttempt> results = invokeConcurrently(2, List.of(
				() -> attempt(this.firstUser.id(), SUBJECT_ID),
				() -> attempt(this.secondUser.id(), SUBJECT_ID)));

		assertSingleWinnerAndGenericConflict(results);
		assertThat(identityCount()).isOne();
	}

	@Test
	void permitsOnlyOneSubjectForAConcurrentUserProviderRace() throws Exception {
		List<LinkAttempt> results = invokeConcurrently(2, List.of(
				() -> attempt(this.firstUser.id(), SUBJECT_ID),
				() -> attempt(this.firstUser.id(), SECOND_SUBJECT_ID)));

		assertSingleWinnerAndGenericConflict(results);
		assertThat(identityCount()).isOne();
	}

	@Test
	void holdsTheUserGuardUntilLinkCommit() throws Exception {
		CountDownLatch linked = new CountDownLatch(1);
		CountDownLatch releaseLink = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger linkBackendId = new AtomicInteger();
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<UserExternalIdentity> link = executor.submit(() -> transactionTemplate().execute(status -> {
				linkBackendId.set(backendId());
				UserExternalIdentity identity =
						this.identities.link(TenantId.DEFAULT, this.firstUser.id(), PROVIDER_ID, SUBJECT_ID);
				linked.countDown();
				await(releaseLink, "Timed out holding the external identity link transaction");
				return identity;
			}));
			Future<User> disable;
			try {
				assertThat(linked.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.users.disable(TenantId.DEFAULT, this.firstUser.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(disableBackendId.get(), linkBackendId.get())).isTrue();
			}
			finally {
				releaseLink.countDown();
			}

			assertThat(link.get(5, TimeUnit.SECONDS)).isEqualTo(stored(SUBJECT_ID));
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
		}
		assertThat(identityCount()).isOne();
	}

	@Test
	void rejectsLinkWhenUserDisableCommitsFirst() throws Exception {
		CountDownLatch disabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch linkStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();
		AtomicInteger linkBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<User> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				disableBackendId.set(backendId());
				User user = this.users.disable(TenantId.DEFAULT, this.firstUser.id());
				disabled.countDown();
				await(releaseDisable, "Timed out holding the user disable transaction");
				return user;
			}));
			Future<UserExternalIdentity> link;
			try {
				assertThat(disabled.await(5, TimeUnit.SECONDS)).isTrue();
				link = executor.submit(() -> transactionTemplate().execute(status -> {
					linkBackendId.set(backendId());
					linkStarted.countDown();
					return this.identities.link(TenantId.DEFAULT, this.firstUser.id(), PROVIDER_ID, SUBJECT_ID);
				}));
				assertThat(linkStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(linkBackendId.get(), disableBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
			assertThatThrownBy(() -> link.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(UserNotActiveException.class);
		}
		assertThat(identityCount()).isZero();
	}

	@Test
	void holdsTheTenantGuardUntilLinkCommit() throws Exception {
		Tenant tenant = createTenant("link-first");
		User user = createUser(tenant.id(), "tenant-link-first");
		CountDownLatch linked = new CountDownLatch(1);
		CountDownLatch releaseLink = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger linkBackendId = new AtomicInteger();
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<UserExternalIdentity> link = executor.submit(() -> transactionTemplate().execute(status -> {
				linkBackendId.set(backendId());
				UserExternalIdentity identity =
						this.identities.link(tenant.id(), user.id(), PROVIDER_ID, SUBJECT_ID);
				linked.countDown();
				await(releaseLink, "Timed out holding the tenant-guarded identity link");
				return identity;
			}));
			Future<Tenant> disable;
			try {
				assertThat(linked.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.tenants.disable(tenant.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(disableBackendId.get(), linkBackendId.get())).isTrue();
			}
			finally {
				releaseLink.countDown();
			}

			assertThat(link.get(5, TimeUnit.SECONDS))
				.isEqualTo(this.identities.findBySubject(tenant.id(), PROVIDER_ID, SUBJECT_ID).orElseThrow());
			assertThat(disable.get(5, TimeUnit.SECONDS).isActive()).isFalse();
		}
		assertThat(identityCount(tenant.id())).isOne();
	}

	@Test
	void rejectsLinkWhenTenantDisableCommitsFirst() throws Exception {
		Tenant tenant = createTenant("disable-first");
		User user = createUser(tenant.id(), "tenant-disable-first");
		CountDownLatch disabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch linkStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();
		AtomicInteger linkBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Tenant> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				disableBackendId.set(backendId());
				Tenant changed = this.tenants.disable(tenant.id());
				disabled.countDown();
				await(releaseDisable, "Timed out holding the tenant disable transaction");
				return changed;
			}));
			Future<UserExternalIdentity> link;
			try {
				assertThat(disabled.await(5, TimeUnit.SECONDS)).isTrue();
				link = executor.submit(() -> transactionTemplate().execute(status -> {
					linkBackendId.set(backendId());
					linkStarted.countDown();
					return this.identities.link(tenant.id(), user.id(), PROVIDER_ID, SUBJECT_ID);
				}));
				assertThat(linkStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(linkBackendId.get(), disableBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).isActive()).isFalse();
			assertThatThrownBy(() -> link.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(TenantDisabledException.class);
		}
		assertThat(identityCount(tenant.id())).isZero();
	}

	private LinkAttempt attempt(UserId userId, ExternalSubjectId subjectId) {
		try {
			return LinkAttempt.linked(this.identities.link(TenantId.DEFAULT, userId, PROVIDER_ID, subjectId));
		}
		catch (ExternalIdentityLinkConflictException exception) {
			return LinkAttempt.conflict(exception);
		}
	}

	private void assertSingleWinnerAndGenericConflict(List<LinkAttempt> results) {
		assertThat(results).filteredOn(LinkAttempt::linked).hasSize(1);
		ExternalIdentityLinkConflictException conflict = results.stream()
			.filter(result -> !result.linked())
			.map(LinkAttempt::conflict)
			.findFirst()
			.orElseThrow();
		assertThat(conflict).hasNoCause();
		assertThat(conflict.getMessage()).doesNotContain(SUBJECT_ID.value(), SECOND_SUBJECT_ID.value());
	}

	private <T> List<T> invokeConcurrently(int callers, Callable<T> operation) throws Exception {
		List<Callable<T>> operations = new ArrayList<>();
		for (int index = 0; index < callers; index++) {
			operations.add(operation);
		}
		return invokeConcurrently(callers, operations);
	}

	private <T> List<T> invokeConcurrently(int callers, List<Callable<T>> operations) throws Exception {
		CountDownLatch ready = new CountDownLatch(callers);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<T>> futures = new ArrayList<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(callers)) {
			for (Callable<T> operation : operations) {
				futures.add(executor.submit(() -> {
					ready.countDown();
					start.await();
					return operation.call();
				}));
			}
			boolean allReady;
			try {
				allReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(allReady).isTrue();

			List<T> results = new ArrayList<>();
			for (Future<T> future : futures) {
				results.add(future.get(10, TimeUnit.SECONDS));
			}
			return results;
		}
	}

	private User createUser(String purpose) {
		return createUser(TenantId.DEFAULT, purpose);
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(tenantId, new CreateUserRequest(
				List.of(LoginIdentifier.username("external-identity-concurrency-" + purpose + "-" + suffix))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		return user;
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest(
				"external-identity-concurrency-" + purpose + "-" + suffix, "External Identity Concurrency"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private UserExternalIdentity stored(ExternalSubjectId subjectId) {
		return this.identities.findBySubject(TenantId.DEFAULT, PROVIDER_ID, subjectId).orElseThrow();
	}

	private int identityCount() {
		return identityCount(TenantId.DEFAULT);
	}

	private int identityCount(TenantId tenantId) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM user_external_identities
				WHERE tenant_id = :tenantId AND provider_id = :providerId
				""")
			.param("tenantId", tenantId.value())
			.param("providerId", PROVIDER_ID.value())
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
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while coordinating external identity operations", exception);
		}
	}

	private record LinkAttempt(UserExternalIdentity identity, ExternalIdentityLinkConflictException conflict) {

		private LinkAttempt {
			if ((identity == null) == (conflict == null)) {
				throw new IllegalArgumentException("A link attempt must contain exactly one outcome");
			}
		}

		static LinkAttempt linked(UserExternalIdentity identity) {
			return new LinkAttempt(identity, null);
		}

		static LinkAttempt conflict(ExternalIdentityLinkConflictException conflict) {
			return new LinkAttempt(null, conflict);
		}

		boolean linked() {
			return this.identity != null;
		}

	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
