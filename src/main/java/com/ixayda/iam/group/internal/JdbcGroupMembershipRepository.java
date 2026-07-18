package com.ixayda.iam.group.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcGroupMembershipRepository {

	private static final Comparator<UserId> USER_ID_ORDER = Comparator.comparing(UserId::value);

	private static final RowMapper<GroupMembership> ROW_MAPPER = JdbcGroupMembershipRepository::mapMembership;

	private final JdbcClient jdbcClient;

	JdbcGroupMembershipRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	Set<GroupMembership> findByGroup(TenantId tenantId, GroupId groupId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(groupId, "Group ID must not be null");
		LinkedHashSet<GroupMembership> memberships = this.jdbcClient.sql("""
				SELECT tenant_id, group_id, user_id, created_at
				FROM group_memberships
				WHERE tenant_id = :tenantId AND group_id = :groupId
				ORDER BY user_id
				""")
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.query(ROW_MAPPER)
			.list()
			.stream()
			.collect(Collectors.toCollection(LinkedHashSet::new));
		return Collections.unmodifiableSet(memberships);
	}

	Optional<Set<GroupMembership>> findByActiveGroup(TenantId tenantId, GroupId groupId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(groupId, "Group ID must not be null");
		List<MembershipRow> rows = this.jdbcClient.sql("""
				SELECT membership.user_id, membership.created_at
				FROM groups group_record
				LEFT JOIN group_memberships membership
				  ON membership.tenant_id = group_record.tenant_id
				 AND membership.group_id = group_record.group_id
				WHERE group_record.tenant_id = :tenantId
				  AND group_record.group_id = :groupId
				  AND group_record.status = :activeStatus
				ORDER BY membership.user_id
				""")
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.param("activeStatus", databaseValue(GroupStatus.ACTIVE))
			.query((resultSet, rowNumber) -> {
				UUID userId = resultSet.getObject("user_id", UUID.class);
				OffsetDateTime createdAt = resultSet.getObject("created_at", OffsetDateTime.class);
				return new MembershipRow(userId, createdAt == null ? null : createdAt.toInstant());
			})
			.list();
		if (rows.isEmpty()) {
			return Optional.empty();
		}
		LinkedHashSet<GroupMembership> memberships = rows.stream()
			.filter(MembershipRow::hasMembership)
			.map(row -> new GroupMembership(tenantId, groupId, new UserId(row.userId()), row.createdAt()))
			.collect(Collectors.toCollection(LinkedHashSet::new));
		return Optional.of(Collections.unmodifiableSet(memberships));
	}

	List<GroupId> findGroupIdsByUser(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		return this.jdbcClient.sql("""
				SELECT group_id
				FROM group_memberships
				WHERE tenant_id = :tenantId AND user_id = :userId
				ORDER BY group_id
				""")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.query((resultSet, rowNumber) -> new GroupId(resultSet.getObject("group_id", UUID.class)))
			.list();
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void replace(Group group, Set<GroupMembership> current, Set<UserId> desiredUserIds, Instant changedAt) {
		Objects.requireNonNull(group, "Group must not be null");
		Objects.requireNonNull(current, "Current group memberships must not be null");
		Objects.requireNonNull(desiredUserIds, "Desired group member IDs must not be null");
		Objects.requireNonNull(changedAt, "Group membership change time must not be null");
		requireWriteTransaction();
		Set<UserId> currentUserIds = current.stream().map(GroupMembership::userId).collect(Collectors.toSet());
		if (currentUserIds.equals(desiredUserIds)) {
			throw new IllegalArgumentException("Replacing group memberships requires a different member set");
		}
		if (current.stream().anyMatch(membership -> !membership.tenantId().equals(group.tenantId())
				|| !membership.groupId().equals(group.id()))) {
			throw new IllegalArgumentException("Current group memberships must belong to the updated group");
		}

		currentUserIds.stream()
			.filter(userId -> !desiredUserIds.contains(userId))
			.sorted(USER_ID_ORDER)
			.forEach(userId -> delete(group, userId));
		desiredUserIds.stream()
			.filter(userId -> !currentUserIds.contains(userId))
			.sorted(USER_ID_ORDER)
			.forEach(userId -> insert(group, userId, changedAt));
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void deleteByGroup(Group group) {
		Objects.requireNonNull(group, "Group must not be null");
		requireWriteTransaction();
		if (group.status() != GroupStatus.ACTIVE) {
			throw new IllegalArgumentException("Only active group memberships can be deleted");
		}
		this.jdbcClient.sql("""
				DELETE FROM group_memberships
				WHERE tenant_id = :tenantId AND group_id = :groupId
				""")
			.param("tenantId", group.tenantId().value())
			.param("groupId", group.id().value())
			.update();
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void deleteForUser(Group group, UserId userId) {
		Objects.requireNonNull(group, "Group must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		requireWriteTransaction();
		int affected = this.jdbcClient.sql("""
				DELETE FROM group_memberships
				WHERE tenant_id = :tenantId AND group_id = :groupId AND user_id = :userId
				""")
			.param("tenantId", group.tenantId().value())
			.param("groupId", group.id().value())
			.param("userId", userId.value())
			.update();
		if (affected != 1) {
			throw new IllegalStateException(
					"Deleting a user's group membership affected an unexpected number of rows: " + affected);
		}
	}

	private void insert(Group group, UserId userId, Instant createdAt) {
		int affected = this.jdbcClient.sql("""
				INSERT INTO group_memberships (tenant_id, group_id, user_id, created_at)
				VALUES (:tenantId, :groupId, :userId, :createdAt)
				""")
			.param("tenantId", group.tenantId().value())
			.param("groupId", group.id().value())
			.param("userId", userId.value())
			.param("createdAt", databaseValue(createdAt))
			.update();
		if (affected != 1) {
			throw new IllegalStateException("Adding a group membership affected an unexpected number of rows: " + affected);
		}
	}

	private void delete(Group group, UserId userId) {
		int affected = this.jdbcClient.sql("""
				DELETE FROM group_memberships
				WHERE tenant_id = :tenantId AND group_id = :groupId AND user_id = :userId
				""")
			.param("tenantId", group.tenantId().value())
			.param("groupId", group.id().value())
			.param("userId", userId.value())
			.update();
		if (affected != 1) {
			throw new IllegalStateException("Removing a group membership affected an unexpected number of rows: " + affected);
		}
	}

	private static GroupMembership mapMembership(ResultSet resultSet, int rowNumber) throws SQLException {
		return new GroupMembership(new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new GroupId(resultSet.getObject("group_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)),
				resultSet.getObject("created_at", OffsetDateTime.class).toInstant());
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static String databaseValue(GroupStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case DELETED -> "deleted";
		};
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Group membership write requires an existing read-write transaction");
		}
	}

	private record MembershipRow(UUID userId, Instant createdAt) {

		private boolean hasMembership() {
			return this.userId != null;
		}

	}

}
