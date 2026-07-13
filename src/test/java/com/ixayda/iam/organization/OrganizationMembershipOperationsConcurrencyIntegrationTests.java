package com.ixayda.iam.organization;

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
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class OrganizationMembershipOperationsConcurrencyIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private OrganizationMembershipOperations memberships;

	@Autowired
	private OrganizationOperations organizations;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	private Organization organization;

	private User user;

	@BeforeEach
	void createParents() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		this.organization = this.organizations.create(TenantId.DEFAULT,
				new CreateOrganizationRequest("membership-concurrency-" + suffix, "Membership Concurrency"));
		this.user = this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("membership-concurrency-" + suffix))));
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM organization_memberships
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("organizationId", this.organization.id().value())
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
		this.jdbcClient.sql("""
				DELETE FROM organizations
				WHERE tenant_id = :tenantId AND organization_id = :organizationId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("organizationId", this.organization.id().value())
			.update();
	}

	@Test
	void convergesConcurrentFirstAdds() throws Exception {
		List<OrganizationMembership> results = invokeConcurrently(8,
				() -> this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id()));

		OrganizationMembership stored = storedMembership();
		assertThat(results).allMatch(stored::equals);
		assertThat(stored.status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
		assertThat(stored.version()).isZero();
		assertThat(membershipCount()).isOne();
	}

	@Test
	void convergesConcurrentRemovals() throws Exception {
		this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id());

		List<OrganizationMembership> results = invokeConcurrently(8,
				() -> this.memberships.removeMember(TenantId.DEFAULT, this.organization.id(), this.user.id()));

		OrganizationMembership stored = storedMembership();
		assertThat(results).allMatch(stored::equals);
		assertThat(stored.status()).isEqualTo(OrganizationMembershipStatus.REMOVED);
		assertThat(stored.version()).isOne();
	}

	@Test
	void convergesConcurrentReactivations() throws Exception {
		this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id());
		this.memberships.removeMember(TenantId.DEFAULT, this.organization.id(), this.user.id());

		List<OrganizationMembership> results = invokeConcurrently(8,
				() -> this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id()));

		OrganizationMembership stored = storedMembership();
		assertThat(results).allMatch(stored::equals);
		assertThat(stored.status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
		assertThat(stored.version()).isEqualTo(2);
	}

	@Test
	void holdsTheOrganizationGuardUntilMembershipAdditionCommits() throws Exception {
		CountDownLatch membershipAdded = new CountDownLatch(1);
		CountDownLatch releaseAddition = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger additionBackendId = new AtomicInteger();
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<OrganizationMembership> addition = executor.submit(() -> transactionTemplate().execute(status -> {
				additionBackendId.set(backendId());
				OrganizationMembership added =
						this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id());
				membershipAdded.countDown();
				await(releaseAddition, "Timed out holding the membership addition transaction");
				return added;
			}));
			Future<Organization> disable;
			try {
				assertThat(membershipAdded.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.organizations.disable(TenantId.DEFAULT, this.organization.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(disableBackendId.get(), additionBackendId.get())).isTrue();
			}
			finally {
				releaseAddition.countDown();
			}

			assertThat(addition.get(5, TimeUnit.SECONDS).status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(OrganizationStatus.DISABLED);
		}
		assertThat(membershipCount()).isOne();
	}

	@Test
	void holdsTheUserGuardUntilMembershipAdditionCommits() throws Exception {
		CountDownLatch membershipAdded = new CountDownLatch(1);
		CountDownLatch releaseAddition = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger additionBackendId = new AtomicInteger();
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<OrganizationMembership> addition = executor.submit(() -> transactionTemplate().execute(status -> {
				additionBackendId.set(backendId());
				OrganizationMembership added =
						this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id());
				membershipAdded.countDown();
				await(releaseAddition, "Timed out holding the membership addition transaction");
				return added;
			}));
			Future<User> disable;
			try {
				assertThat(membershipAdded.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.users.disable(TenantId.DEFAULT, this.user.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(disableBackendId.get(), additionBackendId.get())).isTrue();
			}
			finally {
				releaseAddition.countDown();
			}

			assertThat(addition.get(5, TimeUnit.SECONDS).status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
		}
		assertThat(membershipCount()).isOne();
	}

	@Test
	void rejectsAdditionWhenOrganizationDisableCommitsFirst() throws Exception {
		CountDownLatch organizationDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch additionStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();
		AtomicInteger additionBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Organization> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				disableBackendId.set(backendId());
				Organization disabled = this.organizations.disable(TenantId.DEFAULT, this.organization.id());
				organizationDisabled.countDown();
				await(releaseDisable, "Timed out holding the organization disable transaction");
				return disabled;
			}));
			Future<OrganizationMembership> addition;
			try {
				assertThat(organizationDisabled.await(5, TimeUnit.SECONDS)).isTrue();
				addition = executor.submit(() -> transactionTemplate().execute(status -> {
					additionBackendId.set(backendId());
					additionStarted.countDown();
					return this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id());
				}));
				assertThat(additionStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(additionBackendId.get(), disableBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(OrganizationStatus.DISABLED);
			assertThatThrownBy(() -> addition.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(OrganizationDisabledException.class);
		}
		assertThat(membershipCount()).isZero();
	}

	@Test
	void rejectsAdditionWhenUserDisableCommitsFirst() throws Exception {
		CountDownLatch userDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch additionStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();
		AtomicInteger additionBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<User> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				disableBackendId.set(backendId());
				User disabled = this.users.disable(TenantId.DEFAULT, this.user.id());
				userDisabled.countDown();
				await(releaseDisable, "Timed out holding the user disable transaction");
				return disabled;
			}));
			Future<OrganizationMembership> addition;
			try {
				assertThat(userDisabled.await(5, TimeUnit.SECONDS)).isTrue();
				addition = executor.submit(() -> transactionTemplate().execute(status -> {
					additionBackendId.set(backendId());
					additionStarted.countDown();
					return this.memberships.addMember(TenantId.DEFAULT, this.organization.id(), this.user.id());
				}));
				assertThat(additionStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(additionBackendId.get(), disableBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(UserStatus.DISABLED);
			assertThatThrownBy(() -> addition.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(UserNotActiveException.class);
		}
		assertThat(membershipCount()).isZero();
	}

	private List<OrganizationMembership> invokeConcurrently(int callers, Callable<OrganizationMembership> operation)
			throws Exception {
		CountDownLatch ready = new CountDownLatch(callers);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<OrganizationMembership>> futures = new ArrayList<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(callers)) {
			for (int i = 0; i < callers; i++) {
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

			List<OrganizationMembership> results = new ArrayList<>();
			for (Future<OrganizationMembership> future : futures) {
				results.add(future.get(10, TimeUnit.SECONDS));
			}
			return results;
		}
	}

	private OrganizationMembership storedMembership() {
		return this.memberships.findMembership(TenantId.DEFAULT, this.organization.id(), this.user.id()).orElseThrow();
	}

	private int membershipCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM organization_memberships
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("organizationId", this.organization.id().value())
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
			throw new IllegalStateException("Interrupted while coordinating organization memberships", ex);
		}
	}

}
