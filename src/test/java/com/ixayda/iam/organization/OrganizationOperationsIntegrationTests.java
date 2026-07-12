package com.ixayda.iam.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class OrganizationOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<OrganizationId> organizationsToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private OrganizationOperations organizations;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.organizationsToDelete.forEach(organizationId -> this.jdbcClient
			.sql("DELETE FROM organizations WHERE organization_id = :organizationId")
			.param("organizationId", organizationId.value())
			.update());
		this.tenantsToDelete.forEach(tenantId -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void createsAndFindsAnOrganization() {
		Organization created = create(TenantId.DEFAULT, "engineering", " Engineering ");

		assertThat(created.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(created.displayName()).isEqualTo("Engineering");
		assertThat(created.status()).isEqualTo(OrganizationStatus.ACTIVE);
		assertThat(created.version()).isZero();
		assertThat(this.organizations.findById(TenantId.DEFAULT, created.id())).contains(created);
		assertThat(this.organizations.findBySlug(TenantId.DEFAULT, "engineering")).contains(created);
	}

	@Test
	void rejectsDuplicateSlugsWithinATenant() {
		create(TenantId.DEFAULT, "duplicate", "First");

		assertThatThrownBy(() -> this.organizations.create(TenantId.DEFAULT,
				new CreateOrganizationRequest("duplicate", "Second")))
			.isInstanceOf(OrganizationAlreadyExistsException.class);
	}

	@Test
	void changesStatusIdempotently() {
		Organization created = create(TenantId.DEFAULT, "lifecycle", "Lifecycle");

		Organization disabled = this.organizations.disable(TenantId.DEFAULT, created.id());
		assertThat(disabled.status()).isEqualTo(OrganizationStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(this.organizations.disable(TenantId.DEFAULT, created.id())).isEqualTo(disabled);
		assertThatThrownBy(() -> this.organizations.requireActive(TenantId.DEFAULT, created.id()))
			.isInstanceOf(OrganizationDisabledException.class);

		Organization active = this.organizations.activate(TenantId.DEFAULT, created.id());
		assertThat(active.status()).isEqualTo(OrganizationStatus.ACTIVE);
		assertThat(active.version()).isEqualTo(2);
		assertThat(this.organizations.activate(TenantId.DEFAULT, created.id())).isEqualTo(active);
		assertThat(this.organizations.requireActive(TenantId.DEFAULT, created.id())).isEqualTo(active);
	}

	@Test
	void convergesConcurrentDisables() throws Exception {
		Organization created = create(TenantId.DEFAULT, "concurrent-organization", "Concurrent Organization");
		int callers = 8;
		CountDownLatch ready = new CountDownLatch(callers);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<Organization>> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(callers)) {
			for (int i = 0; i < callers; i++) {
				results.add(executor.submit(() -> {
					ready.countDown();
					start.await();
					return this.organizations.disable(TenantId.DEFAULT, created.id());
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

			List<Organization> transitions = new ArrayList<>();
			for (Future<Organization> result : results) {
				transitions.add(result.get(10, TimeUnit.SECONDS));
			}
			Organization stored = this.organizations.findById(TenantId.DEFAULT, created.id()).orElseThrow();
			assertThat(transitions).allMatch(stored::equals);
			assertThat(stored.status()).isEqualTo(OrganizationStatus.DISABLED);
			assertThat(stored.version()).isOne();
		}
	}

	@Test
	void preventsTenantDisableUntilAnOrganizationWriteCommits() throws Exception {
		Tenant tenant = createTenant("organization-write-guard", "Organization Write Guard");
		CountDownLatch organizationCreated = new CountDownLatch(1);
		CountDownLatch releaseWrite = new CountDownLatch(1);

		try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
			Future<Organization> guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				Organization created = this.organizations.create(tenant.id(),
						new CreateOrganizationRequest("guarded", "Guarded"));
				this.organizationsToDelete.add(created.id());
				organizationCreated.countDown();
				await(releaseWrite);
				return created;
			}));

			assertThat(organizationCreated.await(5, TimeUnit.SECONDS)).isTrue();
			try {
				Throwable lockTimeout = catchThrowable(() -> transactionTemplate().executeWithoutResult(status -> {
					this.jdbcClient.sql("SET LOCAL lock_timeout = '1s'").update();
					this.tenants.disable(tenant.id());
				}));
				assertThat(lockTimeout).isInstanceOf(DataAccessException.class);
				assertThat(((DataAccessException) lockTimeout).getRootCause())
					.isInstanceOfSatisfying(SQLException.class,
							ex -> assertThat(ex.getSQLState()).isEqualTo("55P03"));
				assertThat(this.tenants.requireActive(tenant.id())).isEqualTo(tenant);
			}
			finally {
				releaseWrite.countDown();
			}

			Organization created = guardedWrite.get(5, TimeUnit.SECONDS);
			assertThat(this.organizations.findById(tenant.id(), created.id())).contains(created);
		}

		assertThat(this.tenants.disable(tenant.id()).isActive()).isFalse();
	}

	@Test
	void rejectsAnOrganizationWriteWhenAConcurrentTenantDisableCommitsFirst() throws Exception {
		Tenant tenant = createTenant("disable-before-organization", "Disable Before Organization");
		CountDownLatch tenantDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch organizationWriteStarted = new CountDownLatch(1);
		AtomicInteger organizationBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Tenant> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				Tenant disabled = this.tenants.disable(tenant.id());
				tenantDisabled.countDown();
				await(releaseDisable);
				return disabled;
			}));
			assertThat(tenantDisabled.await(5, TimeUnit.SECONDS)).isTrue();

			Future<Organization> organizationWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				organizationBackendId.set(this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single());
				organizationWriteStarted.countDown();
				Organization created = this.organizations.create(tenant.id(),
						new CreateOrganizationRequest("blocked-by-disable", "Blocked by Disable"));
				this.organizationsToDelete.add(created.id());
				return created;
			}));

			try {
				assertThat(organizationWriteStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(organizationBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).isActive()).isFalse();
			assertThatThrownBy(() -> organizationWrite.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(TenantDisabledException.class);
			assertThat(this.organizations.findBySlug(tenant.id(), "blocked-by-disable")).isEmpty();
		}
	}

	@Test
	void doesNotExposeAnOrganizationThroughAnotherTenant() {
		Organization created = create(TenantId.DEFAULT, "isolated", "Isolated");
		Tenant secondTenant = createTenant("organization-isolation", "Organization Isolation");

		assertThat(this.organizations.findById(secondTenant.id(), created.id())).isEmpty();
		assertThatThrownBy(() -> this.organizations.disable(secondTenant.id(), created.id()))
			.isInstanceOf(OrganizationNotFoundException.class);
		assertThat(this.organizations.findById(TenantId.DEFAULT, created.id())).contains(created);
	}

	@Test
	void rejectsWritesAndActiveAccessForADisabledTenant() {
		Tenant tenant = createTenant("disabled-organization-tenant", "Disabled Organization Tenant");
		Organization organization = create(tenant.id(), "existing", "Existing");
		this.tenants.disable(tenant.id());

		assertThatThrownBy(() -> this.organizations.create(tenant.id(),
				new CreateOrganizationRequest("blocked", "Blocked"))).isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.organizations.requireActive(tenant.id(), organization.id()))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.organizations.disable(tenant.id(), organization.id()))
			.isInstanceOf(TenantDisabledException.class);
	}

	@Test
	void toleratesAStoredTimestampAheadOfTheSystemClock() {
		Organization created = create(TenantId.DEFAULT, "future-organization", "Future Organization");
		Instant future = created.updatedAt().plusSeconds(3_600);
		this.jdbcClient.sql("UPDATE organizations SET updated_at = :updatedAt WHERE organization_id = :organizationId")
			.param("updatedAt", OffsetDateTime.ofInstant(future, ZoneOffset.UTC))
			.param("organizationId", created.id().value())
			.update();

		Organization disabled = this.organizations.disable(TenantId.DEFAULT, created.id());

		assertThat(disabled.status()).isEqualTo(OrganizationStatus.DISABLED);
		assertThat(disabled.updatedAt()).isEqualTo(future);
	}

	private Organization create(TenantId tenantId, String slug, String displayName) {
		Organization organization =
				this.organizations.create(tenantId, new CreateOrganizationRequest(slug, displayName));
		this.organizationsToDelete.add(organization.id());
		return organization;
	}

	private Tenant createTenant(String slug, String displayName) {
		Tenant tenant = this.tenants.create(new CreateTenantRequest(slug, displayName));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
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

	private static void await(CountDownLatch latch) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Timed out waiting to release the organization write");
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while holding the organization write transaction", ex);
		}
	}

}
