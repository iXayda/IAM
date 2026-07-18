package com.ixayda.iam.group;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class GroupMembershipSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID GROUP_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f151");

	private static final UUID USER_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f152");

	private static final UUID SECOND_GROUP_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f153");

	private static final UUID SECOND_USER_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f154");

	private static final UUID SECOND_TENANT_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f155");

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createFixtures() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'group-membership-schema', 'Group Membership Schema')
				""").param("tenantId", SECOND_TENANT_ID).update();
		insertGroup(GROUP_ID, TenantId.DEFAULT.value(), "Default Group");
		insertUser(USER_ID, TenantId.DEFAULT.value());
		insertGroup(SECOND_GROUP_ID, SECOND_TENANT_ID, "Second Group");
		insertUser(SECOND_USER_ID, SECOND_TENANT_ID);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM group_memberships WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM groups WHERE group_id IN (:firstGroupId, :secondGroupId)")
			.param("firstGroupId", GROUP_ID)
			.param("secondGroupId", SECOND_GROUP_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesDirectUserMembershipsWithCreationTimeAndUniqueness() {
		insertMembership(TenantId.DEFAULT.value(), GROUP_ID, USER_ID);

		assertThat(this.jdbcClient.sql("""
				SELECT created_at IS NOT NULL
				FROM group_memberships
				WHERE tenant_id = :tenantId AND group_id = :groupId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("groupId", GROUP_ID)
			.param("userId", USER_ID)
			.query(Boolean.class)
			.single()).isTrue();
		assertThatThrownBy(() -> insertMembership(TenantId.DEFAULT.value(), GROUP_ID, USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void rejectsUnknownAndCrossTenantParents() {
		assertThatThrownBy(() -> insertMembership(TenantId.DEFAULT.value(), SECOND_GROUP_ID, USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertMembership(TenantId.DEFAULT.value(), GROUP_ID, SECOND_USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertMembership(TenantId.DEFAULT.value(), UUID.randomUUID(), USER_ID))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertMembership(TenantId.DEFAULT.value(), GROUP_ID, UUID.randomUUID()))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void restrictsPhysicalParentDeletionAndIndexesReverseLookup() {
		insertMembership(TenantId.DEFAULT.value(), GROUP_ID, USER_ID);

		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM groups WHERE group_id = :groupId")
			.param("groupId", GROUP_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(this.jdbcClient.sql("""
				SELECT indexdef FROM pg_indexes
				WHERE schemaname = current_schema()
				  AND indexname = 'group_memberships_user_group_idx'
				""").query(String.class).single()).contains("(tenant_id, user_id, group_id)");
	}

	private void insertMembership(UUID tenantId, UUID groupId, UUID userId) {
		this.jdbcClient.sql("""
				INSERT INTO group_memberships (tenant_id, group_id, user_id)
				VALUES (:tenantId, :groupId, :userId)
				""")
			.param("tenantId", tenantId)
			.param("groupId", groupId)
			.param("userId", userId)
			.update();
	}

	private void insertGroup(UUID groupId, UUID tenantId, String displayName) {
		this.jdbcClient.sql("""
				INSERT INTO groups (group_id, tenant_id, display_name)
				VALUES (:groupId, :tenantId, :displayName)
				""")
			.param("groupId", groupId)
			.param("tenantId", tenantId)
			.param("displayName", displayName)
			.update();
	}

	private void insertUser(UUID userId, UUID tenantId) {
		this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id)
				VALUES (:userId, :tenantId)
				""")
			.param("userId", userId)
			.param("tenantId", tenantId)
			.update();
	}

}
