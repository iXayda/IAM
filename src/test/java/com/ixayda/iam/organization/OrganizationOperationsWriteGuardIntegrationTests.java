package com.ixayda.iam.organization;

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
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class OrganizationOperationsWriteGuardIntegrationTests extends ApplicationIntegrationTest {

	private final List<OrganizationId> organizationsToDelete = new ArrayList<>();

	@Autowired
	private OrganizationOperations organizations;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.organizationsToDelete.forEach(organizationId -> this.jdbcClient
			.sql("DELETE FROM organizations WHERE tenant_id = :tenantId AND organization_id = :organizationId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("organizationId", organizationId.value())
			.update());
	}

	@Test
	void preventsOrganizationDisableUntilTheGuardedWriteCommits() throws Exception {
		Organization organization = createOrganization("guard-first");
		CountDownLatch guardAcquired = new CountDownLatch(1);
		CountDownLatch releaseGuard = new CountDownLatch(1);
		CountDownLatch disableStarted = new CountDownLatch(1);
		AtomicInteger guardBackendId = new AtomicInteger();
		AtomicInteger disableBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Organization> guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				guardBackendId.set(backendId());
				Organization active = this.organizations.requireActiveForWrite(TenantId.DEFAULT, organization.id());
				guardAcquired.countDown();
				await(releaseGuard, "Timed out holding the organization write guard");
				return active;
			}));
			Future<Organization> disable;
			try {
				assertThat(guardAcquired.await(5, TimeUnit.SECONDS)).isTrue();
				disable = executor.submit(() -> transactionTemplate().execute(status -> {
					disableBackendId.set(backendId());
					disableStarted.countDown();
					return this.organizations.disable(TenantId.DEFAULT, organization.id());
				}));
				assertThat(disableStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(disableBackendId.get(), guardBackendId.get())).isTrue();
			}
			finally {
				releaseGuard.countDown();
			}

			assertThat(guardedWrite.get(5, TimeUnit.SECONDS)).isEqualTo(organization);
			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(OrganizationStatus.DISABLED);
		}
	}

	@Test
	void rejectsTheGuardedWriteWhenOrganizationDisableCommitsFirst() throws Exception {
		Organization organization = createOrganization("disable-first");
		CountDownLatch organizationDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch guardStarted = new CountDownLatch(1);
		AtomicInteger disableBackendId = new AtomicInteger();
		AtomicInteger guardBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Organization> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				disableBackendId.set(backendId());
				Organization disabled = this.organizations.disable(TenantId.DEFAULT, organization.id());
				organizationDisabled.countDown();
				await(releaseDisable, "Timed out holding the organization disable transaction");
				return disabled;
			}));
			Future<Organization> guardedWrite;
			try {
				assertThat(organizationDisabled.await(5, TimeUnit.SECONDS)).isTrue();
				guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
					guardBackendId.set(backendId());
					guardStarted.countDown();
					return this.organizations.requireActiveForWrite(TenantId.DEFAULT, organization.id());
				}));
				assertThat(guardStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlockedBy(guardBackendId.get(), disableBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).status()).isEqualTo(OrganizationStatus.DISABLED);
			assertThatThrownBy(() -> guardedWrite.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(OrganizationDisabledException.class);
		}
	}

	@Test
	void requiresAReadWriteTransactionWithoutPoisoningExpectedFailures() {
		Organization organization = createOrganization("transaction-contract");

		assertThatThrownBy(() -> this.organizations.requireActiveForWrite(TenantId.DEFAULT, organization.id()))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(
				status -> this.organizations.requireActiveForWrite(TenantId.DEFAULT, organization.id())))
			.isInstanceOf(IllegalTransactionStateException.class);

		Organization disabled = this.organizations.disable(TenantId.DEFAULT, organization.id());
		Organization stored = transactionTemplate().execute(status -> {
			assertThatThrownBy(
					() -> this.organizations.requireActiveForWrite(TenantId.DEFAULT, organization.id()))
				.isInstanceOf(OrganizationDisabledException.class);
			return this.organizations.findById(TenantId.DEFAULT, organization.id()).orElseThrow();
		});
		assertThat(stored).isEqualTo(disabled);
	}

	private Organization createOrganization(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Organization organization = this.organizations.create(TenantId.DEFAULT,
				new CreateOrganizationRequest("write-guard-" + purpose + "-" + suffix, "Write Guard"));
		this.organizationsToDelete.add(organization.id());
		return organization;
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
			throw new IllegalStateException("Interrupted while coordinating organization writes", ex);
		}
	}

}
