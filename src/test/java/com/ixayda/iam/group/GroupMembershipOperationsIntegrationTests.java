package com.ixayda.iam.group;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
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
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class GroupMembershipOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<GroupId> groupsToDelete = new ArrayList<>();

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private GroupOperations groups;

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
		this.groupsToDelete.forEach(groupId -> this.jdbcClient.sql("DELETE FROM group_memberships WHERE group_id = :groupId")
			.param("groupId", groupId.value())
			.update());
		this.usersToDelete.forEach(reference -> this.jdbcClient.sql("""
				DELETE FROM user_login_identifiers
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", reference.tenantId().value())
			.param("userId", reference.userId().value())
			.update());
		this.usersToDelete.forEach(reference -> this.jdbcClient.sql("""
				DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", reference.tenantId().value())
			.param("userId", reference.userId().value())
			.update());
		this.groupsToDelete.forEach(groupId -> this.jdbcClient.sql("DELETE FROM groups WHERE group_id = :groupId")
			.param("groupId", groupId.value())
			.update());
		this.tenantsToDelete.reversed()
			.forEach(tenantId -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update());
	}

	@Test
	void replacesMembersAtomicallyAndAdvancesDirectoryRevisions() {
		Group group = createGroup(TenantId.DEFAULT, "Engineering");
		User active = createUser(TenantId.DEFAULT, "membership-active");
		User disabled = this.users.disable(TenantId.DEFAULT, createUser(TenantId.DEFAULT, "membership-disabled").id());
		User locked = this.users.lock(TenantId.DEFAULT, createUser(TenantId.DEFAULT, "membership-locked").id());

		Group populated = this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(),
				Set.of(active.id(), disabled.id(), locked.id()));

		assertThat(populated.version()).isOne();
		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id()))
			.extracting(GroupMembership::userId)
			.containsExactlyInAnyOrder(active.id(), disabled.id(), locked.id());
		User activeAfterAdd = requireUser(TenantId.DEFAULT, active.id());
		User disabledAfterAdd = requireUser(TenantId.DEFAULT, disabled.id());
		User lockedAfterAdd = requireUser(TenantId.DEFAULT, locked.id());
		assertThat(activeAfterAdd.version()).isEqualTo(active.version() + 1);
		assertThat(disabledAfterAdd.version()).isEqualTo(disabled.version() + 1);
		assertThat(lockedAfterAdd.version()).isEqualTo(locked.version() + 1);
		assertThat(activeAfterAdd.securityVersion()).isEqualTo(active.securityVersion());
		assertThat(disabledAfterAdd.securityVersion()).isEqualTo(disabled.securityVersion());
		assertThat(lockedAfterAdd.securityVersion()).isEqualTo(locked.securityVersion());

		Set<GroupMembership> beforeNoOp = this.groups.findMembers(TenantId.DEFAULT, group.id());
		Group noOp = this.groups.replaceMembers(TenantId.DEFAULT, group.id(), populated.version(),
				Set.of(locked.id(), active.id(), disabled.id()));
		assertThat(noOp).isEqualTo(populated);
		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id())).isEqualTo(beforeNoOp);
		assertThat(requireUser(TenantId.DEFAULT, active.id())).isEqualTo(activeAfterAdd);

		User newcomer = createUser(TenantId.DEFAULT, "membership-newcomer");
		Group mixed = this.groups.replaceMembers(TenantId.DEFAULT, group.id(), noOp.version(),
				Set.of(disabled.id(), locked.id(), newcomer.id()));
		assertThat(mixed.version()).isEqualTo(2);
		assertThat(membershipFor(group.id(), disabled.id()).createdAt())
			.isEqualTo(membershipFor(beforeNoOp, disabled.id()).createdAt());
		assertThat(membershipFor(group.id(), locked.id()).createdAt())
			.isEqualTo(membershipFor(beforeNoOp, locked.id()).createdAt());
		assertThat(requireUser(TenantId.DEFAULT, active.id()).version()).isEqualTo(activeAfterAdd.version() + 1);
		assertThat(requireUser(TenantId.DEFAULT, disabled.id())).isEqualTo(disabledAfterAdd);
		assertThat(requireUser(TenantId.DEFAULT, locked.id())).isEqualTo(lockedAfterAdd);
		User newcomerAfterAdd = requireUser(TenantId.DEFAULT, newcomer.id());
		assertThat(newcomerAfterAdd.version()).isEqualTo(newcomer.version() + 1);

		Group cleared = this.groups.replaceMembers(TenantId.DEFAULT, group.id(), mixed.version(), Set.of());
		assertThat(cleared.version()).isEqualTo(3);
		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id())).isEmpty();
		assertThat(requireUser(TenantId.DEFAULT, disabled.id()).version()).isEqualTo(disabledAfterAdd.version() + 1);
		assertThat(requireUser(TenantId.DEFAULT, locked.id()).version()).isEqualTo(lockedAfterAdd.version() + 1);
		assertThat(requireUser(TenantId.DEFAULT, newcomer.id()).version()).isEqualTo(newcomerAfterAdd.version() + 1);
	}

	@Test
	void rejectsInvalidUsersAndRollsBackTheWholeReplacement() {
		Group group = createGroup(TenantId.DEFAULT, "Rollback");
		User valid = createUser(TenantId.DEFAULT, "membership-valid");
		User deleted = this.users.delete(TenantId.DEFAULT, createUser(TenantId.DEFAULT, "membership-deleted").id());
		Tenant other = createTenant("membership-other");
		User crossTenant = createUser(other.id(), "membership-cross-tenant");

		assertThatThrownBy(() -> this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(),
				Set.of(valid.id(), deleted.id()))).isInstanceOf(UserNotFoundException.class);
		assertUnchanged(group, valid);
		assertThatThrownBy(() -> this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(),
				Set.of(crossTenant.id()))).isInstanceOf(UserNotFoundException.class);
		assertUnchanged(group, valid);
		assertThatThrownBy(() -> this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(),
				Set.of(UserId.random()))).isInstanceOf(UserNotFoundException.class);
		assertUnchanged(group, valid);
	}

	@Test
	void groupDeletionClearsMembershipsAndAdvancesMemberRevisions() {
		Group group = createGroup(TenantId.DEFAULT, "Disposable");
		User user = createUser(TenantId.DEFAULT, "membership-group-delete");
		Group populated = this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(), Set.of(user.id()));
		User afterAdd = requireUser(TenantId.DEFAULT, user.id());

		Group deleted = this.groups.delete(TenantId.DEFAULT, group.id(), populated.version());

		assertThat(deleted.isDeleted()).isTrue();
		assertThat(membershipCount(group.id())).isZero();
		assertThat(requireUser(TenantId.DEFAULT, user.id()).version()).isEqualTo(afterAdd.version() + 1);
		assertThatThrownBy(() -> this.groups.findMembers(TenantId.DEFAULT, group.id()))
			.isInstanceOf(GroupNotFoundException.class);
	}

	@Test
	void userDeletionRemovesMembershipsAndAdvancesEveryGroupRevision() {
		User user = createUser(TenantId.DEFAULT, "membership-user-delete");
		Group first = createGroup(TenantId.DEFAULT, "First");
		Group second = createGroup(TenantId.DEFAULT, "Second");
		first = this.groups.replaceMembers(TenantId.DEFAULT, first.id(), first.version(), Set.of(user.id()));
		second = this.groups.replaceMembers(TenantId.DEFAULT, second.id(), second.version(), Set.of(user.id()));

		User deleted = this.users.delete(TenantId.DEFAULT, user.id());

		assertThat(deleted.status()).isEqualTo(UserStatus.DELETED);
		assertThat(this.groups.findMembers(TenantId.DEFAULT, first.id())).isEmpty();
		assertThat(this.groups.findMembers(TenantId.DEFAULT, second.id())).isEmpty();
		assertThat(this.groups.findById(TenantId.DEFAULT, first.id()).orElseThrow().version())
			.isEqualTo(first.version() + 1);
		assertThat(this.groups.findById(TenantId.DEFAULT, second.id()).orElseThrow().version())
			.isEqualTo(second.version() + 1);
	}

	@Test
	void allowsOnlyOneReplacementForTheSameExpectedVersion() throws Exception {
		Group group = createGroup(TenantId.DEFAULT, "Concurrent");
		User first = createUser(TenantId.DEFAULT, "membership-concurrent-first");
		User second = createUser(TenantId.DEFAULT, "membership-concurrent-second");
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<ReplacementResult>> pending = new ArrayList<>();
		List<ReplacementResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> replace(group, Set.of(first.id()), ready, start)));
			pending.add(executor.submit(() -> replace(group, Set.of(second.id()), ready, start)));
			assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
			start.countDown();
			for (Future<ReplacementResult> result : pending) {
				results.add(result.get(10, TimeUnit.SECONDS));
			}
		}

		assertThat(results.stream().filter(result -> result.group() != null)).hasSize(1);
		assertThat(results.stream().filter(result -> result.failure() != null))
			.singleElement()
			.satisfies(result -> assertThat(result.failure()).isInstanceOf(GroupConcurrentUpdateException.class));
		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id()))
			.extracting(GroupMembership::userId)
			.singleElement()
			.isIn(first.id(), second.id());
	}

	@Test
	void userDeletionWaitsForAnInFlightMembershipWriteThenRemovesIt() throws Exception {
		Group group = createGroup(TenantId.DEFAULT, "Delete After Replacement");
		User user = createUser(TenantId.DEFAULT, "membership-delete-after-write");
		CountDownLatch replaced = new CountDownLatch(1);
		CountDownLatch releaseReplacement = new CountDownLatch(1);
		AtomicInteger deleteBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Group> replacement = executor.submit(() -> transactionTemplate().execute(status -> {
				Group changed = this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(), Set.of(user.id()));
				replaced.countDown();
				await(releaseReplacement);
				return changed;
			}));
			assertThat(replaced.await(5, TimeUnit.SECONDS)).isTrue();

			Future<User> deletion = executor.submit(() -> transactionTemplate().execute(status -> {
				deleteBackendId.set(this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single());
				return this.users.delete(TenantId.DEFAULT, user.id());
			}));
			try {
				assertThat(waitUntilBlocked(deleteBackendId)).isTrue();
			}
			finally {
				releaseReplacement.countDown();
			}

			assertThat(replacement.get(5, TimeUnit.SECONDS).version()).isOne();
			assertThat(deletion.get(5, TimeUnit.SECONDS).isDeleted()).isTrue();
		}

		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id())).isEmpty();
		assertThat(this.groups.findById(TenantId.DEFAULT, group.id()).orElseThrow().version()).isEqualTo(2);
	}

	@Test
	void membershipWriteWaitsForAnInFlightUserDeletionThenRejectsTheUser() throws Exception {
		Group group = createGroup(TenantId.DEFAULT, "Replacement After Delete");
		User user = createUser(TenantId.DEFAULT, "membership-write-after-delete");
		CountDownLatch deleted = new CountDownLatch(1);
		CountDownLatch releaseDeletion = new CountDownLatch(1);
		AtomicInteger replacementBackendId = new AtomicInteger();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<User> deletion = executor.submit(() -> transactionTemplate().execute(status -> {
				User changed = this.users.delete(TenantId.DEFAULT, user.id());
				deleted.countDown();
				await(releaseDeletion);
				return changed;
			}));
			assertThat(deleted.await(5, TimeUnit.SECONDS)).isTrue();

			Future<RuntimeException> replacement = executor.submit(() -> {
				try {
					transactionTemplate().executeWithoutResult(status -> {
						replacementBackendId
							.set(this.jdbcClient.sql("SELECT pg_backend_pid()").query(Integer.class).single());
						this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(), Set.of(user.id()));
					});
					return null;
				}
				catch (RuntimeException ex) {
					return ex;
				}
			});
			try {
				assertThat(waitUntilBlocked(replacementBackendId)).isTrue();
			}
			finally {
				releaseDeletion.countDown();
			}

			assertThat(deletion.get(5, TimeUnit.SECONDS).isDeleted()).isTrue();
			assertThat(replacement.get(5, TimeUnit.SECONDS)).isInstanceOf(UserNotFoundException.class);
		}

		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id())).isEmpty();
		assertThat(this.groups.findById(TenantId.DEFAULT, group.id())).contains(group);
	}

	@Test
	void replacementAndGroupDeletionNeverLeavePartialMemberships() throws Exception {
		Group group = createGroup(TenantId.DEFAULT, "Replacement Delete Race");
		User user = createUser(TenantId.DEFAULT, "membership-group-race");
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<ReplacementResult>> pending = new ArrayList<>();
		List<ReplacementResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> replace(group, Set.of(user.id()), ready, start)));
			pending.add(executor.submit(() -> delete(group, ready, start)));
			assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
			start.countDown();
			for (Future<ReplacementResult> result : pending) {
				results.add(result.get(10, TimeUnit.SECONDS));
			}
		}

		assertThat(results.stream().filter(result -> result.group() != null)).hasSize(1);
		assertThat(results.stream().filter(result -> result.failure() != null))
			.singleElement()
			.satisfies(result -> assertThat(result.failure())
				.isInstanceOfAny(GroupConcurrentUpdateException.class, GroupNotFoundException.class));
		this.groups.findById(TenantId.DEFAULT, group.id()).ifPresentOrElse(active -> {
			assertThat(active.version()).isOne();
			assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id()))
				.extracting(GroupMembership::userId)
				.containsExactly(user.id());
		}, () -> assertThat(membershipCount(group.id())).isZero());
	}

	private ReplacementResult replace(Group group, Set<UserId> memberIds, CountDownLatch ready, CountDownLatch start) {
		ready.countDown();
		await(start);
		try {
			return new ReplacementResult(
					this.groups.replaceMembers(TenantId.DEFAULT, group.id(), group.version(), memberIds), null);
		}
		catch (RuntimeException ex) {
			return new ReplacementResult(null, ex);
		}
	}

	private ReplacementResult delete(Group group, CountDownLatch ready, CountDownLatch start) {
		ready.countDown();
		await(start);
		try {
			return new ReplacementResult(this.groups.delete(TenantId.DEFAULT, group.id(), group.version()), null);
		}
		catch (RuntimeException ex) {
			return new ReplacementResult(null, ex);
		}
	}

	private void assertUnchanged(Group group, User user) {
		assertThat(this.groups.findById(TenantId.DEFAULT, group.id())).contains(group);
		assertThat(this.groups.findMembers(TenantId.DEFAULT, group.id())).isEmpty();
		assertThat(requireUser(TenantId.DEFAULT, user.id())).isEqualTo(user);
	}

	private Group createGroup(TenantId tenantId, String displayName) {
		Group group = this.groups.create(tenantId, new CreateGroupRequest(displayName));
		this.groupsToDelete.add(group.id());
		return group;
	}

	private User createUser(TenantId tenantId, String prefix) {
		String suffix = UUID.randomUUID().toString().replace("-", "");
		User user = this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(prefix + "-" + suffix))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		return user;
	}

	private Tenant createTenant(String prefix) {
		String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
		Tenant tenant = this.tenants.create(new CreateTenantRequest(prefix + "-" + suffix, "Membership Other"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User requireUser(TenantId tenantId, UserId userId) {
		return this.users.findById(tenantId, userId).orElseThrow();
	}

	private int membershipCount(GroupId groupId) {
		return this.jdbcClient.sql("SELECT count(*) FROM group_memberships WHERE group_id = :groupId")
			.param("groupId", groupId.value())
			.query(Integer.class)
			.single();
	}

	private GroupMembership membershipFor(GroupId groupId, UserId userId) {
		return membershipFor(this.groups.findMembers(TenantId.DEFAULT, groupId), userId);
	}

	private static GroupMembership membershipFor(Set<GroupMembership> memberships, UserId userId) {
		return memberships.stream().filter(membership -> membership.userId().equals(userId)).findFirst().orElseThrow();
	}

	private boolean waitUntilBlocked(AtomicInteger backendId) {
		for (int attempt = 0; attempt < 100; attempt++) {
			int pid = backendId.get();
			if (pid != 0 && this.jdbcClient.sql("""
					SELECT wait_event_type = 'Lock'
					FROM pg_stat_activity
					WHERE pid = :pid
					""").param("pid", pid).query(Boolean.class).optional().orElse(false)) {
				return true;
			}
			try {
				Thread.sleep(25);
			}
			catch (InterruptedException ex) {
				Thread.currentThread().interrupt();
				throw new IllegalStateException("Interrupted while waiting for a membership lock", ex);
			}
		}
		return false;
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private static void await(CountDownLatch latch) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Timed out coordinating group membership replacements");
			}
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted coordinating group membership replacements", ex);
		}
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

	private record ReplacementResult(Group group, RuntimeException failure) {
	}

}
