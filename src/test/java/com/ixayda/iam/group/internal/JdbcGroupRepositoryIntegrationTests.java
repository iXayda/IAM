package com.ixayda.iam.group.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupConcurrentUpdateException;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcGroupRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f131"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final List<GroupId> groupsToDelete = new ArrayList<>();

	@Autowired
	private JdbcGroupRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createSecondTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'group-repository', 'Group Repository')
				""").param("tenantId", SECOND_TENANT_ID.value()).update();
	}

	@AfterEach
	void deleteFixtures() {
		this.groupsToDelete.forEach(groupId -> this.jdbcClient.sql("DELETE FROM groups WHERE group_id = :groupId")
			.param("groupId", groupId.value())
			.update());
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void storesAndFindsGroupsWithinTheirTenant() {
		Group group = insert(group(TenantId.DEFAULT, "Engineering", GroupStatus.ACTIVE, 0, CREATED_AT));

		assertThat(this.repository.findById(TenantId.DEFAULT, group.id())).contains(group);
		assertThat(this.repository.findById(SECOND_TENANT_ID, group.id())).isEmpty();
	}

	@Test
	void updatesAndDeletesWithTenantScopedOptimisticLocking() {
		Group current = insert(group(TenantId.DEFAULT, "Engineering", GroupStatus.ACTIVE, 0, CREATED_AT));
		Group renamed = current.updateDisplayName("Platform", CREATED_AT.plusSeconds(1));

		assertThat(updateDisplayName(current, renamed)).isEqualTo(renamed);
		assertThatThrownBy(() -> updateDisplayName(current, renamed))
			.isInstanceOf(GroupConcurrentUpdateException.class);
		Group deleted = renamed.delete(CREATED_AT.plusSeconds(2));
		assertThat(delete(renamed, deleted)).isEqualTo(deleted);
		assertThat(this.repository.findById(TenantId.DEFAULT, current.id())).contains(deleted);
	}

	@Test
	void updatesMembershipRevisionsWithTenantScopedOptimisticLocking() {
		Group current = insert(group(TenantId.DEFAULT, "Engineering", GroupStatus.ACTIVE, 0, CREATED_AT));
		Group changed = current.membersChanged(CREATED_AT.plusSeconds(1));

		assertThat(updateMembers(current, changed)).isEqualTo(changed);
		assertThat(this.repository.findById(TenantId.DEFAULT, current.id())).contains(changed);
		assertThatThrownBy(() -> updateMembers(current, changed))
			.isInstanceOf(GroupConcurrentUpdateException.class);
	}

	@Test
	void rejectsForgedGroupChanges() {
		Group current = group(TenantId.DEFAULT, "Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);
		Group moved = new Group(current.id(), SECOND_TENANT_ID, "Platform", GroupStatus.ACTIVE, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1));
		Group changedStatus = new Group(current.id(), current.tenantId(), "Platform", GroupStatus.DELETED, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1));
		Group skippedVersion = new Group(current.id(), current.tenantId(), "Platform", GroupStatus.ACTIVE, 2,
				current.createdAt(), current.updatedAt().plusSeconds(1));
		Group changedProfileOnDelete = new Group(current.id(), current.tenantId(), "Platform", GroupStatus.DELETED, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1));
		Group changedProfileOnMembers = new Group(current.id(), current.tenantId(), "Platform", GroupStatus.ACTIVE, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1));
		Group skippedMemberVersion = new Group(current.id(), current.tenantId(), current.displayName(), GroupStatus.ACTIVE,
				2, current.createdAt(), current.updatedAt().plusSeconds(1));

		assertThatThrownBy(() -> updateDisplayName(current, moved)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> updateDisplayName(current, changedStatus)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> updateDisplayName(current, skippedVersion)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> delete(current, changedProfileOnDelete)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> updateMembers(current, changedProfileOnMembers))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> updateMembers(current, skippedMemberVersion))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void requiresExistingReadWriteTransactionsForWritesAndLocks() {
		Group group = group(TenantId.DEFAULT, "Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);

		assertThatThrownBy(() -> this.repository.insert(group)).isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.repository.updateMembers(group, group.membersChanged(CREATED_AT.plusSeconds(1))))
			.isInstanceOf(IllegalTransactionStateException.class);
		insert(group);
		assertThatThrownBy(() -> this.repository.findByIdForUpdate(TenantId.DEFAULT, group.id()))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.findByIdForUpdate(TenantId.DEFAULT,
				group.id()))).isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Group write requires an existing read-write transaction");
		Optional<Group> locked = transactionTemplate()
			.execute(status -> this.repository.findByIdForUpdate(TenantId.DEFAULT, group.id()));
		assertThat(locked).contains(group);
	}

	private Group group(TenantId tenantId, String displayName, GroupStatus status, long version, Instant updatedAt) {
		Group group = new Group(GroupId.random(), tenantId, displayName, status, version, CREATED_AT, updatedAt);
		this.groupsToDelete.add(group.id());
		return group;
	}

	private Group insert(Group group) {
		return transactionTemplate().execute(status -> this.repository.insert(group));
	}

	private Group updateDisplayName(Group current, Group changed) {
		return transactionTemplate().execute(status -> this.repository.updateDisplayName(current, changed));
	}

	private Group delete(Group current, Group changed) {
		return transactionTemplate().execute(status -> this.repository.delete(current, changed));
	}

	private Group updateMembers(Group current, Group changed) {
		return transactionTemplate().execute(status -> this.repository.updateMembers(current, changed));
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

}
