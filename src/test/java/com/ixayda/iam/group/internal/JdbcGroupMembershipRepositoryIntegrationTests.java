package com.ixayda.iam.group.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcGroupMembershipRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final GroupId GROUP_ID =
			new GroupId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f161"));

	private static final UserId FIRST_USER_ID =
			new UserId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f162"));

	private static final UserId SECOND_USER_ID =
			new UserId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f163"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Autowired
	private JdbcGroupMembershipRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createFixtures() {
		this.jdbcClient.sql("""
				INSERT INTO groups
				    (group_id, tenant_id, display_name, created_at, updated_at)
				VALUES (:groupId, :tenantId, 'Repository Group', :createdAt, :createdAt)
				""")
			.param("groupId", GROUP_ID.value())
			.param("tenantId", TenantId.DEFAULT.value())
			.param("createdAt", databaseValue(CREATED_AT))
			.update();
		insertUser(FIRST_USER_ID);
		insertUser(SECOND_USER_ID);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM group_memberships WHERE group_id = :groupId")
			.param("groupId", GROUP_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", FIRST_USER_ID.value())
			.param("secondUserId", SECOND_USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM groups WHERE group_id = :groupId")
			.param("groupId", GROUP_ID.value())
			.update();
	}

	@Test
	void distinguishesActiveEmptyGroupsFromMissingAndDeletedGroups() {
		assertThat(this.repository.findByActiveGroup(TenantId.DEFAULT, GROUP_ID)).contains(Set.of());
		assertThat(this.repository.findByActiveGroup(TenantId.DEFAULT, GroupId.random())).isEmpty();

		this.jdbcClient.sql("UPDATE groups SET status = 'deleted' WHERE group_id = :groupId")
			.param("groupId", GROUP_ID.value())
			.update();
		assertThat(this.repository.findByActiveGroup(TenantId.DEFAULT, GROUP_ID)).isEmpty();
	}

	@Test
	void appliesADeltaAndPreservesRetainedMembershipCreationTime() {
		Instant retainedAt = CREATED_AT.plusSeconds(1);
		Instant changedAt = CREATED_AT.plusSeconds(2);
		insertMembership(FIRST_USER_ID, retainedAt);
		Set<GroupMembership> current = this.repository.findByGroup(TenantId.DEFAULT, GROUP_ID);

		transactionTemplate().executeWithoutResult(
				status -> this.repository.replace(group(), current, Set.of(FIRST_USER_ID, SECOND_USER_ID), changedAt));

		assertThat(this.repository.findByGroup(TenantId.DEFAULT, GROUP_ID))
			.extracting(GroupMembership::userId, GroupMembership::createdAt)
			.containsExactlyInAnyOrder(
					org.assertj.core.groups.Tuple.tuple(FIRST_USER_ID, retainedAt),
					org.assertj.core.groups.Tuple.tuple(SECOND_USER_ID, changedAt));
		assertThatThrownBy(() -> this.repository.findByGroup(TenantId.DEFAULT, GROUP_ID).clear())
			.isInstanceOf(UnsupportedOperationException.class);

		transactionTemplate().executeWithoutResult(status -> this.repository.deleteByGroup(group()));
		assertThat(this.repository.findByGroup(TenantId.DEFAULT, GROUP_ID)).isEmpty();
	}

	@Test
	void rejectsNoOpForgedAndNonTransactionalWrites() {
		Group group = group();
		GroupMembership membership = new GroupMembership(TenantId.DEFAULT, GROUP_ID, FIRST_USER_ID, CREATED_AT);
		GroupMembership forged = new GroupMembership(TenantId.DEFAULT, GroupId.random(), FIRST_USER_ID, CREATED_AT);

		assertThatThrownBy(() -> transactionTemplate().executeWithoutResult(
				status -> this.repository.replace(group, Set.of(membership), Set.of(FIRST_USER_ID), CREATED_AT)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> transactionTemplate().executeWithoutResult(
				status -> this.repository.replace(group, Set.of(forged), Set.of(SECOND_USER_ID), CREATED_AT)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.repository.replace(group, Set.of(), Set.of(FIRST_USER_ID), CREATED_AT))
			.isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.repository.deleteByGroup(group))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.executeWithoutResult(
				status -> this.repository.replace(group, Set.of(), Set.of(FIRST_USER_ID), CREATED_AT)))
			.isInstanceOf(IllegalTransactionStateException.class);
	}

	private Group group() {
		return new Group(GROUP_ID, TenantId.DEFAULT, "Repository Group", GroupStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

	private void insertUser(UserId userId) {
		this.jdbcClient.sql("INSERT INTO users (user_id, tenant_id) VALUES (:userId, :tenantId)")
			.param("userId", userId.value())
			.param("tenantId", TenantId.DEFAULT.value())
			.update();
	}

	private void insertMembership(UserId userId, Instant createdAt) {
		this.jdbcClient.sql("""
				INSERT INTO group_memberships (tenant_id, group_id, user_id, created_at)
				VALUES (:tenantId, :groupId, :userId, :createdAt)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("groupId", GROUP_ID.value())
			.param("userId", userId.value())
			.param("createdAt", databaseValue(createdAt))
			.update();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

}
