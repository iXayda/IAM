package com.ixayda.iam.group;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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

class GroupOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<GroupId> groupsToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private GroupOperations groups;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.groupsToDelete.forEach(groupId -> this.jdbcClient.sql("DELETE FROM groups WHERE group_id = :groupId")
			.param("groupId", groupId.value())
			.update());
		this.tenantsToDelete.reversed()
			.forEach(tenantId -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update());
	}

	@Test
	void createsAndFindsGroupsWithoutRequiringUniqueDisplayNames() {
		Group first = create(TenantId.DEFAULT, " Platform Administrators ");
		Group second = create(TenantId.DEFAULT, "Platform Administrators");

		assertThat(first.id()).isNotEqualTo(second.id());
		assertThat(first.displayName()).isEqualTo("Platform Administrators");
		assertThat(first.status()).isEqualTo(GroupStatus.ACTIVE);
		assertThat(first.version()).isZero();
		assertThat(this.groups.findById(TenantId.DEFAULT, first.id())).contains(first);
		assertThat(this.groups.findById(TenantId.DEFAULT, second.id())).contains(second);
	}

	@Test
	void updatesDisplayNamesWithExplicitOptimisticConcurrency() {
		Group created = create(TenantId.DEFAULT, "Engineering");

		Group renamed = this.groups.updateDisplayName(TenantId.DEFAULT, created.id(), created.version(), " Platform ");

		assertThat(renamed.displayName()).isEqualTo("Platform");
		assertThat(renamed.version()).isOne();
		assertThat(renamed.updatedAt()).isAfterOrEqualTo(created.updatedAt());
		assertThat(this.groups.findById(TenantId.DEFAULT, created.id())).contains(renamed);
		assertThatThrownBy(() -> this.groups.updateDisplayName(TenantId.DEFAULT, created.id(), created.version(),
				"Stale")).isInstanceOf(GroupConcurrentUpdateException.class)
			.extracting("tenantId", "groupId", "expectedVersion")
			.containsExactly(TenantId.DEFAULT, created.id(), 0L);
		assertThat(this.groups.updateDisplayName(TenantId.DEFAULT, renamed.id(), renamed.version(), "Platform"))
			.isEqualTo(renamed);
	}

	@Test
	void softDeletesGroupsAndHidesTheirTombstones() {
		Group created = create(TenantId.DEFAULT, "Temporary");

		Group deleted = this.groups.delete(TenantId.DEFAULT, created.id(), created.version());

		assertThat(deleted.isDeleted()).isTrue();
		assertThat(deleted.version()).isOne();
		assertThat(this.groups.findById(TenantId.DEFAULT, created.id())).isEmpty();
		assertThatThrownBy(() -> this.groups.delete(TenantId.DEFAULT, created.id(), deleted.version()))
			.isInstanceOf(GroupNotFoundException.class);
		assertThatThrownBy(() -> this.groups.updateDisplayName(TenantId.DEFAULT, created.id(), deleted.version(),
				"Restored")).isInstanceOf(GroupNotFoundException.class);
		assertThat(this.jdbcClient.sql("SELECT status FROM groups WHERE group_id = :groupId")
			.param("groupId", created.id().value())
			.query(String.class)
			.single()).isEqualTo("deleted");
	}

	@Test
	void doesNotExposeOrUpdateGroupsAcrossTenants() {
		Group created = create(TenantId.DEFAULT, "Isolated");
		Tenant other = createTenant("group-isolation");

		assertThat(this.groups.findById(other.id(), created.id())).isEmpty();
		assertThatThrownBy(() -> this.groups.updateDisplayName(other.id(), created.id(), created.version(), "Moved"))
			.isInstanceOf(GroupNotFoundException.class);
		assertThat(this.groups.findById(TenantId.DEFAULT, created.id())).contains(created);
	}

	@Test
	void rejectsWritesForDisabledTenants() {
		Tenant tenant = createTenant("disabled-group");
		Group group = create(tenant.id(), "Existing");
		this.tenants.disable(tenant.id());

		assertThatThrownBy(() -> this.groups.create(tenant.id(), new CreateGroupRequest("Blocked")))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.groups.updateDisplayName(tenant.id(), group.id(), group.version(), "Blocked"))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.groups.delete(tenant.id(), group.id(), group.version()))
			.isInstanceOf(TenantDisabledException.class);
	}

	@Test
	void allowsOnlyOneUpdateForTheSameExpectedVersion() throws Exception {
		Group created = create(TenantId.DEFAULT, "Concurrent");
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<UpdateResult>> pending = new ArrayList<>();
		List<UpdateResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> update(created, "First", ready, start)));
			pending.add(executor.submit(() -> update(created, "Second", ready, start)));
			boolean bothReady;
			try {
				bothReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(bothReady).isTrue();
			for (Future<UpdateResult> result : pending) {
				results.add(result.get(10, TimeUnit.SECONDS));
			}
		}

		assertThat(results.stream().filter(result -> result.group() != null)).hasSize(1);
		assertThat(results.stream().filter(result -> result.failure() != null))
			.singleElement()
			.satisfies(result -> assertThat(result.failure()).isInstanceOf(GroupConcurrentUpdateException.class));
		Group stored = this.groups.findById(TenantId.DEFAULT, created.id()).orElseThrow();
		assertThat(stored.version()).isOne();
		assertThat(stored.displayName()).isIn("First", "Second");
	}

	@Test
	void doesNotResurrectAGroupWhenRenameAndDeleteRace() throws Exception {
		Group created = create(TenantId.DEFAULT, "Race");
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<UpdateResult>> pending = new ArrayList<>();
		List<UpdateResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> update(created, "Renamed", ready, start)));
			pending.add(executor.submit(() -> delete(created, ready, start)));
			boolean bothReady;
			try {
				bothReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(bothReady).isTrue();
			for (Future<UpdateResult> result : pending) {
				results.add(result.get(10, TimeUnit.SECONDS));
			}
		}

		assertThat(results.stream().filter(result -> result.group() != null)).hasSize(1);
		assertThat(results.stream().filter(result -> result.failure() != null))
			.singleElement()
			.satisfies(result -> assertThat(result.failure())
				.isInstanceOfAny(GroupConcurrentUpdateException.class, GroupNotFoundException.class));
		assertThat(this.jdbcClient.sql("""
				SELECT status || '|' || display_name || '|' || version
				FROM groups WHERE tenant_id = :tenantId AND group_id = :groupId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("groupId", created.id().value())
			.query(String.class)
			.single()).isIn("active|Renamed|1", "deleted|Race|1");
	}

	@Test
	void preventsTenantDisableUntilAGroupWriteCommits() throws Exception {
		Tenant tenant = createTenant("group-write-guard");
		CountDownLatch groupCreated = new CountDownLatch(1);
		CountDownLatch releaseWrite = new CountDownLatch(1);

		try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
			Future<Group> guardedWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				Group created = this.groups.create(tenant.id(), new CreateGroupRequest("Guarded"));
				this.groupsToDelete.add(created.id());
				groupCreated.countDown();
				await(releaseWrite);
				return created;
			}));

			assertThat(groupCreated.await(5, TimeUnit.SECONDS)).isTrue();
			try {
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

			Group created = guardedWrite.get(5, TimeUnit.SECONDS);
			assertThat(this.groups.findById(tenant.id(), created.id())).contains(created);
		}

		assertThat(this.tenants.disable(tenant.id()).isActive()).isFalse();
	}

	@Test
	void rejectsAGroupWriteWhenAConcurrentTenantDisableCommitsFirst() throws Exception {
		Tenant tenant = createTenant("disable-before-group");
		Group group = create(tenant.id(), "Existing");
		CountDownLatch tenantDisabled = new CountDownLatch(1);
		CountDownLatch releaseDisable = new CountDownLatch(1);
		CountDownLatch groupWriteStarted = new CountDownLatch(1);
		AtomicInteger groupBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Tenant> disable = executor.submit(() -> transactionTemplate().execute(status -> {
				Tenant disabled = this.tenants.disable(tenant.id());
				tenantDisabled.countDown();
				await(releaseDisable);
				return disabled;
			}));
			assertThat(tenantDisabled.await(5, TimeUnit.SECONDS)).isTrue();

			Future<Group> groupWrite = executor.submit(() -> transactionTemplate().execute(status -> {
				groupBackendId.set(this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single());
				groupWriteStarted.countDown();
				return this.groups.updateDisplayName(tenant.id(), group.id(), group.version(), "Blocked");
			}));

			try {
				assertThat(groupWriteStarted.await(5, TimeUnit.SECONDS)).isTrue();
				assertThat(waitUntilBlocked(groupBackendId.get())).isTrue();
			}
			finally {
				releaseDisable.countDown();
			}

			assertThat(disable.get(5, TimeUnit.SECONDS).isActive()).isFalse();
			assertThatThrownBy(() -> groupWrite.get(5, TimeUnit.SECONDS))
				.hasCauseInstanceOf(TenantDisabledException.class);
			assertThat(this.groups.findById(tenant.id(), group.id())).contains(group);
		}
	}

	@Test
	void toleratesAStoredTimestampAheadOfTheSystemClock() {
		Group created = create(TenantId.DEFAULT, "Future");
		Instant future = created.updatedAt().plusSeconds(3_600);
		this.jdbcClient.sql("UPDATE groups SET updated_at = :updatedAt WHERE group_id = :groupId")
			.param("updatedAt", OffsetDateTime.ofInstant(future, ZoneOffset.UTC))
			.param("groupId", created.id().value())
			.update();

		Group renamed = this.groups.updateDisplayName(TenantId.DEFAULT, created.id(), created.version(), "Future Name");

		assertThat(renamed.updatedAt()).isEqualTo(future);
	}

	private Group create(TenantId tenantId, String displayName) {
		Group group = this.groups.create(tenantId, new CreateGroupRequest(displayName));
		this.groupsToDelete.add(group.id());
		return group;
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants
			.create(new CreateTenantRequest(purpose + "-" + suffix, "Group Test Tenant"));
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
				throw new IllegalStateException("Timed out waiting to release the group write");
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while holding the group write transaction", ex);
		}
	}

	private UpdateResult update(Group group, String displayName, CountDownLatch ready, CountDownLatch start) {
		try {
			ready.countDown();
			start.await();
			return new UpdateResult(this.groups.updateDisplayName(group.tenantId(), group.id(), group.version(),
					displayName), null);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			return new UpdateResult(null, new IllegalStateException("Interrupted while updating a group", ex));
		}
		catch (RuntimeException ex) {
			return new UpdateResult(null, ex);
		}
	}

	private UpdateResult delete(Group group, CountDownLatch ready, CountDownLatch start) {
		try {
			ready.countDown();
			start.await();
			return new UpdateResult(this.groups.delete(group.tenantId(), group.id(), group.version()), null);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			return new UpdateResult(null, new IllegalStateException("Interrupted while deleting a group", ex));
		}
		catch (RuntimeException ex) {
			return new UpdateResult(null, ex);
		}
	}

	private record UpdateResult(Group group, RuntimeException failure) {
	}

}
