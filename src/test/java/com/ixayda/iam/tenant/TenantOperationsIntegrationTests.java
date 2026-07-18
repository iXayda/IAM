package com.ixayda.iam.tenant;

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

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class TenantOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteCreatedTenants() {
		this.tenantsToDelete.forEach(tenantId -> this.jdbcClient
			.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void createsAndFindsATenant() {
		Tenant created = create("acme", " Acme ");

		assertThat(created.id()).isNotEqualTo(TenantId.DEFAULT);
		assertThat(created.displayName()).isEqualTo("Acme");
		assertThat(created.status()).isEqualTo(TenantStatus.ACTIVE);
		assertThat(created.version()).isZero();
		assertThat(this.tenants.findById(created.id())).contains(created);
		assertThat(this.tenants.findBySlug("acme")).contains(created);
	}

	@Test
	void rejectsDuplicateSlugs() {
		create("duplicate", "First");

		assertThatThrownBy(() -> this.tenants.create(new CreateTenantRequest("duplicate", "Second")))
			.isInstanceOf(TenantAlreadyExistsException.class);
	}

	@Test
	void changesStatusIdempotently() {
		Tenant created = create("lifecycle", "Lifecycle");

		Tenant disabled = this.tenants.disable(created.id());
		assertThat(disabled.status()).isEqualTo(TenantStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(this.tenants.disable(created.id())).isEqualTo(disabled);
		assertThatThrownBy(() -> this.tenants.requireActive(created.id()))
			.isInstanceOf(TenantDisabledException.class);

		Tenant active = this.tenants.activate(created.id());
		assertThat(active.status()).isEqualTo(TenantStatus.ACTIVE);
		assertThat(active.version()).isEqualTo(2);
		assertThat(this.tenants.activate(created.id())).isEqualTo(active);
		assertThat(this.tenants.requireActive(created.id())).isEqualTo(active);
	}

	@Test
	void requiresAnExistingTransactionForTheWriteGuard() {
		assertThatThrownBy(() -> this.tenants.requireActiveForWrite(TenantId.DEFAULT))
			.isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.tenants.requireActiveForExclusiveWrite(TenantId.DEFAULT))
			.isInstanceOf(IllegalTransactionStateException.class);
	}

	@Test
	void requiresAReadWriteTransactionForTheWriteGuard() {
		TransactionTemplate transaction = transactionTemplate();
		transaction.setReadOnly(true);

		assertThatThrownBy(
				() -> transaction.executeWithoutResult(status -> this.tenants.requireActiveForWrite(TenantId.DEFAULT)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Tenant write guard requires a read-write transaction");
		assertThatThrownBy(() -> transaction
			.executeWithoutResult(status -> this.tenants.requireActiveForExclusiveWrite(TenantId.DEFAULT)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Exclusive tenant write guard requires a read-write transaction");
	}

	@Test
	void exclusiveGuardBlocksConcurrentTenantScopedWrites() throws Exception {
		Tenant created = create("exclusive-write-guard", "Exclusive Write Guard");
		CountDownLatch guardAcquired = new CountDownLatch(1);
		CountDownLatch releaseGuard = new CountDownLatch(1);

		try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
			Future<Tenant> exclusiveWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				Tenant guarded = this.tenants.requireActiveForExclusiveWrite(created.id());
				guardAcquired.countDown();
				await(releaseGuard);
				return guarded;
			}));

			assertThat(guardAcquired.await(5, TimeUnit.SECONDS)).isTrue();
			try {
				Throwable lockTimeout = catchThrowable(() -> transactionTemplate().executeWithoutResult(status -> {
					this.jdbcClient.sql("SET LOCAL lock_timeout = '1s'").update();
					this.tenants.requireActiveForWrite(created.id());
				}));
				assertThat(lockTimeout).isInstanceOf(DataAccessException.class);
				assertThat(((DataAccessException) lockTimeout).getRootCause())
					.isInstanceOfSatisfying(SQLException.class,
							ex -> assertThat(ex.getSQLState()).isEqualTo("55P03"));
			}
			finally {
				releaseGuard.countDown();
			}

			assertThat(exclusiveWrite.get(5, TimeUnit.SECONDS)).isEqualTo(created);
		}
	}

	@Test
	void preventsTenantDisableUntilAGuardedWriteCompletes() throws Exception {
		Tenant created = create("write-guard", "Write Guard");
		CountDownLatch guardAcquired = new CountDownLatch(1);
		CountDownLatch releaseGuard = new CountDownLatch(1);

		try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
			Future<Tenant> guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				Tenant guarded = this.tenants.requireActiveForWrite(created.id());
				guardAcquired.countDown();
				await(releaseGuard);
				return guarded;
			}));

			assertThat(guardAcquired.await(5, TimeUnit.SECONDS)).isTrue();
			try {
				Throwable lockTimeout = catchThrowable(() -> transactionTemplate().executeWithoutResult(status -> {
					this.jdbcClient.sql("SET LOCAL lock_timeout = '1s'").update();
					this.tenants.disable(created.id());
				}));
				assertThat(lockTimeout).isInstanceOf(DataAccessException.class);
				assertThat(((DataAccessException) lockTimeout).getRootCause())
					.isInstanceOfSatisfying(SQLException.class,
							ex -> assertThat(ex.getSQLState()).isEqualTo("55P03"));
				assertThat(this.tenants.requireActive(created.id())).isEqualTo(created);
			}
			finally {
				releaseGuard.countDown();
			}

			assertThat(guardedWrite.get(5, TimeUnit.SECONDS)).isEqualTo(created);
		}

		assertThat(this.tenants.disable(created.id()).status()).isEqualTo(TenantStatus.DISABLED);
	}

	@Test
	void convergesConcurrentDisables() throws Exception {
		Tenant created = create("concurrent-disable", "Concurrent Disable");
		int callers = 8;
		CountDownLatch ready = new CountDownLatch(callers);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<Tenant>> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(callers)) {
			for (int i = 0; i < callers; i++) {
				results.add(executor.submit(() -> {
					ready.countDown();
					start.await();
					return this.tenants.disable(created.id());
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

			List<Tenant> transitions = new ArrayList<>();
			for (Future<Tenant> result : results) {
				transitions.add(result.get(10, TimeUnit.SECONDS));
			}
			Tenant stored = this.tenants.findById(created.id()).orElseThrow();
			assertThat(transitions).allMatch(stored::equals);
			assertThat(stored.status()).isEqualTo(TenantStatus.DISABLED);
			assertThat(stored.version()).isOne();
		}
	}

	@Test
	void toleratesAStoredTimestampAheadOfTheSystemClock() {
		Tenant created = create("future-timestamp", "Future Timestamp");
		Instant future = created.updatedAt().plusSeconds(3_600);
		this.jdbcClient.sql("UPDATE tenants SET updated_at = :updatedAt WHERE tenant_id = :tenantId")
			.param("updatedAt", OffsetDateTime.ofInstant(future, ZoneOffset.UTC))
			.param("tenantId", created.id().value())
			.update();

		Tenant disabled = this.tenants.disable(created.id());

		assertThat(disabled.status()).isEqualTo(TenantStatus.DISABLED);
		assertThat(disabled.updatedAt()).isEqualTo(future);
	}

	@Test
	void reportsMissingAndProtectedTenants() {
		TenantId missing = TenantId.random();

		assertThatThrownBy(() -> this.tenants.requireActive(missing)).isInstanceOf(TenantNotFoundException.class);
		assertThatThrownBy(() -> this.tenants.disable(TenantId.DEFAULT)).isInstanceOf(ProtectedTenantException.class);
		assertThat(this.tenants.requireActive(TenantId.DEFAULT).isBuiltInDefault()).isTrue();
	}

	private Tenant create(String slug, String displayName) {
		Tenant tenant = this.tenants.create(new CreateTenantRequest(slug, displayName));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private static void await(CountDownLatch latch) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Timed out waiting to release the tenant write guard");
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while holding the tenant write guard", ex);
		}
	}

}
