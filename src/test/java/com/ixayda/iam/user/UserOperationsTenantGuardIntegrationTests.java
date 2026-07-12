package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.sql.SQLException;
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

class UserOperationsTenantGuardIntegrationTests extends ApplicationIntegrationTest {

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
	void preventsTenantDisableUntilAUserWriteCommits() throws Exception {
		Tenant tenant = createTenant("user-first");
		CountDownLatch userCreated = new CountDownLatch(1);
		CountDownLatch releaseWrite = new CountDownLatch(1);

		try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
			Future<User> guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				User created = this.users.create(tenant.id(),
						new CreateUserRequest(List.of(LoginIdentifier.username("guarded-user"))));
				userCreated.countDown();
				await(releaseWrite, "Timed out holding the user write transaction");
				return created;
			}));

			try {
				assertThat(userCreated.await(5, TimeUnit.SECONDS)).isTrue();
				Throwable lockTimeout = catchThrowable(() -> transactionTemplate().executeWithoutResult(status -> {
					this.jdbcClient.sql("SET LOCAL lock_timeout = '1s'").update();
					this.tenants.disable(tenant.id());
				}));
				assertThat(lockTimeout).isInstanceOf(DataAccessException.class);
				assertThat(((DataAccessException) lockTimeout).getRootCause())
					.isInstanceOfSatisfying(SQLException.class,
							exception -> assertThat(exception.getSQLState()).isEqualTo("55P03"));
				assertThat(this.tenants.requireActive(tenant.id())).isEqualTo(tenant);
			}
			finally {
				releaseWrite.countDown();
			}

			User created = guardedWrite.get(5, TimeUnit.SECONDS);
			assertThat(this.users.findById(tenant.id(), created.id())).contains(created);
		}

		assertThat(this.tenants.disable(tenant.id()).isActive()).isFalse();
	}

	@Test
	void rejectsAUserWriteWhenAConcurrentTenantDisableCommitsFirst() throws Exception {
		Tenant tenant = createTenant("tenant-first");
		LoginIdentifier username = LoginIdentifier.username("blocked-by-disable");
		CountDownLatch tenantDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch userWriteStarted = new CountDownLatch(1);
		AtomicInteger userBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Tenant> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				Tenant disabled = this.tenants.disable(tenant.id());
				tenantDisabled.countDown();
				await(releaseDisable, "Timed out holding the tenant disable transaction");
				return disabled;
			}));
			Future<User> userWrite;
			try {
				assertThat(tenantDisabled.await(5, TimeUnit.SECONDS)).isTrue();
				userWrite = executor.submit(() -> transactionTemplate().execute(status -> {
					int backendId = this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single();
					userBackendId.set(backendId);
					userWriteStarted.countDown();
					return this.users.create(tenant.id(), new CreateUserRequest(List.of(username)));
				}));
				assertThat(userWriteStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(userBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).isActive()).isFalse();
			assertThatThrownBy(() -> userWrite.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(TenantDisabledException.class);
			assertThat(this.users.findByLogin(tenant.id(), username.loginKey())).isEmpty();
			assertThat(userRows(tenant.id())).isZero();
		}
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants
			.create(new CreateTenantRequest("user-guard-" + purpose + "-" + suffix, "User Guard Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private int userRows(TenantId tenantId) {
		return this.jdbcClient.sql("SELECT count(*) FROM users WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.query(Integer.class)
			.single();
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
			throw new IllegalStateException("Interrupted while coordinating tenant and user writes", ex);
		}
	}

}
