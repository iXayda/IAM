package com.ixayda.iam.group.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupConcurrentUpdateException;
import com.ixayda.iam.group.GroupDirectoryQuery;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupPage;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.TenantId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcGroupRepository {

	private static final String COLUMNS =
			"group_id, tenant_id, display_name, status, version, created_at, updated_at";

	private static final RowMapper<Group> GROUP_ROW_MAPPER = JdbcGroupRepository::mapGroup;

	private static final ResultSetExtractor<GroupPage> GROUP_PAGE_EXTRACTOR = JdbcGroupRepository::extractGroupPage;

	private static final String ACTIVE_GROUP_CONDITION = "g.status = 'active'";

	private static final String NO_GROUPS_CONDITION = "false";

	private static final String ID_EQUALS_CONDITION = ACTIVE_GROUP_CONDITION + " AND g.group_id = :matchedGroupId";

	private static final String DISPLAY_NAME_EQUALS_CONDITION =
			ACTIVE_GROUP_CONDITION + " AND lower(g.display_name) = lower(:matchedDisplayName)";

	private final JdbcClient jdbcClient;

	JdbcGroupRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Group insert(Group group) {
		Objects.requireNonNull(group, "Group must not be null");
		requireWriteTransaction();
		if (group.status() != GroupStatus.ACTIVE || group.version() != 0
				|| !group.createdAt().equals(group.updatedAt())) {
			throw new IllegalArgumentException("New group must be active at version zero and start at its creation time");
		}
		int affected = this.jdbcClient.sql("""
				INSERT INTO groups
				    (group_id, tenant_id, display_name, status, version, created_at, updated_at)
				VALUES
				    (:groupId, :tenantId, :displayName, :status, :version, :createdAt, :updatedAt)
				""")
			.param("groupId", group.id().value())
			.param("tenantId", group.tenantId().value())
			.param("displayName", group.displayName())
			.param("status", databaseValue(group.status()))
			.param("version", group.version())
			.param("createdAt", databaseValue(group.createdAt()))
			.param("updatedAt", databaseValue(group.updatedAt()))
			.update();
		if (affected != 1) {
			throw new IllegalStateException("Creating a group affected an unexpected number of rows: " + affected);
		}
		return group;
	}

	Optional<Group> findById(TenantId tenantId, GroupId groupId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(groupId, "Group ID must not be null");
		return this.jdbcClient
			.sql("SELECT " + COLUMNS + " FROM groups WHERE tenant_id = :tenantId AND group_id = :groupId")
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.query(GROUP_ROW_MAPPER)
			.optional();
	}

	GroupPage findDirectoryPage(TenantId tenantId, GroupDirectoryQuery query) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(query, "Group directory query must not be null");
		String condition = switch (query.criterion()) {
			case GroupDirectoryQuery.All ignored -> ACTIVE_GROUP_CONDITION;
			case GroupDirectoryQuery.None ignored -> NO_GROUPS_CONDITION;
			case GroupDirectoryQuery.IdEquals ignored -> ID_EQUALS_CONDITION;
			case GroupDirectoryQuery.DisplayNameEquals ignored -> DISPLAY_NAME_EQUALS_CONDITION;
		};
		JdbcClient.StatementSpec statement = this.jdbcClient.sql(directoryPageQuery(condition))
			.param("tenantId", tenantId.value())
			.param("offset", query.offset())
			.param("limit", query.limit());
		if (query.criterion() instanceof GroupDirectoryQuery.IdEquals idEquals) {
			statement = statement.param("matchedGroupId", idEquals.groupId().value());
		}
		else if (query.criterion() instanceof GroupDirectoryQuery.DisplayNameEquals displayNameEquals) {
			statement = statement.param("matchedDisplayName", displayNameEquals.value());
		}
		return statement.query(GROUP_PAGE_EXTRACTOR);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<Group> findByIdForUpdate(TenantId tenantId, GroupId groupId) {
		return findByIdWithLock(tenantId, groupId, "FOR UPDATE");
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = GroupConcurrentUpdateException.class)
	Group updateDisplayName(Group current, Group changed) {
		Objects.requireNonNull(current, "Current group must not be null");
		Objects.requireNonNull(changed, "Changed group must not be null");
		requireWriteTransaction();
		if (!sameIdentity(current, changed) || current.displayName().equals(changed.displayName())
				|| current.status() != changed.status() || current.status() != GroupStatus.ACTIVE
				|| current.version() == Long.MAX_VALUE || changed.version() != current.version() + 1
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Group display name update must preserve ownership and lifecycle state, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE groups
				SET display_name = :displayName, version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND group_id = :groupId
				  AND display_name = :expectedDisplayName
				  AND status = :expectedStatus
				  AND version = :expectedVersion
				""")
			.param("displayName", changed.displayName())
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("groupId", current.id().value())
			.param("expectedDisplayName", current.displayName())
			.param("expectedStatus", databaseValue(current.status()))
			.param("expectedVersion", current.version())
			.update();
		return requireSingleUpdate(current, changed, affected);
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = GroupConcurrentUpdateException.class)
	Group delete(Group current, Group changed) {
		Objects.requireNonNull(current, "Current group must not be null");
		Objects.requireNonNull(changed, "Changed group must not be null");
		requireWriteTransaction();
		if (!sameIdentity(current, changed) || !current.displayName().equals(changed.displayName())
				|| current.status() != GroupStatus.ACTIVE || changed.status() != GroupStatus.DELETED
				|| current.version() == Long.MAX_VALUE || changed.version() != current.version() + 1
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Group deletion must preserve ownership and profile, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE groups
				SET status = :newStatus, version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND group_id = :groupId
				  AND display_name = :expectedDisplayName
				  AND status = :expectedStatus
				  AND version = :expectedVersion
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("groupId", current.id().value())
			.param("expectedDisplayName", current.displayName())
			.param("expectedStatus", databaseValue(current.status()))
			.param("expectedVersion", current.version())
			.update();
		return requireSingleUpdate(current, changed, affected);
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = GroupConcurrentUpdateException.class)
	Group updateMembers(Group current, Group changed) {
		Objects.requireNonNull(current, "Current group must not be null");
		Objects.requireNonNull(changed, "Changed group must not be null");
		requireWriteTransaction();
		if (!sameIdentity(current, changed) || !current.displayName().equals(changed.displayName())
				|| current.status() != GroupStatus.ACTIVE || changed.status() != GroupStatus.ACTIVE
				|| current.version() == Long.MAX_VALUE || changed.version() != current.version() + 1
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Group membership update must preserve ownership and profile, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE groups
				SET version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND group_id = :groupId
				  AND display_name = :expectedDisplayName
				  AND status = :expectedStatus
				  AND version = :expectedVersion
				""")
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("groupId", current.id().value())
			.param("expectedDisplayName", current.displayName())
			.param("expectedStatus", databaseValue(current.status()))
			.param("expectedVersion", current.version())
			.update();
		return requireSingleUpdate(current, changed, affected);
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = GroupConcurrentUpdateException.class)
	Group replace(Group current, Group changed) {
		Objects.requireNonNull(current, "Current group must not be null");
		Objects.requireNonNull(changed, "Changed group must not be null");
		requireWriteTransaction();
		if (!sameIdentity(current, changed) || current.status() != GroupStatus.ACTIVE
				|| changed.status() != GroupStatus.ACTIVE || current.version() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1 || changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Group replacement must preserve ownership and lifecycle state, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE groups
				SET display_name = :displayName, version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND group_id = :groupId
				  AND display_name = :expectedDisplayName
				  AND status = :expectedStatus
				  AND version = :expectedVersion
				""")
			.param("displayName", changed.displayName())
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("groupId", current.id().value())
			.param("expectedDisplayName", current.displayName())
			.param("expectedStatus", databaseValue(current.status()))
			.param("expectedVersion", current.version())
			.update();
		return requireSingleUpdate(current, changed, affected);
	}

	private Optional<Group> findByIdWithLock(TenantId tenantId, GroupId groupId, String lockClause) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(groupId, "Group ID must not be null");
		requireWriteTransaction();
		return this.jdbcClient
			.sql("SELECT " + COLUMNS
					+ " FROM groups WHERE tenant_id = :tenantId AND group_id = :groupId " + lockClause)
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.query(GROUP_ROW_MAPPER)
			.optional();
	}

	private static Group requireSingleUpdate(Group current, Group changed, int affected) {
		if (affected == 0) {
			throw new GroupConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating a group affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private static boolean sameIdentity(Group current, Group changed) {
		return current.id().equals(changed.id()) && current.tenantId().equals(changed.tenantId())
				&& current.createdAt().equals(changed.createdAt());
	}

	private static Group mapGroup(ResultSet resultSet, int rowNumber) throws SQLException {
		return new Group(new GroupId(resultSet.getObject("group_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)), resultSet.getString("display_name"),
				status(resultSet.getString("status")), resultSet.getLong("version"),
				resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

	private static GroupPage extractGroupPage(ResultSet resultSet) throws SQLException {
		if (!resultSet.next()) {
			throw new IllegalStateException("Group directory query did not return its total result row");
		}
		long totalResults = resultSet.getLong("total_results");
		ArrayList<Group> groups = new ArrayList<>();
		do {
			if (resultSet.getObject("group_id") != null) {
				groups.add(mapGroup(resultSet, groups.size()));
			}
		}
		while (resultSet.next());
		return new GroupPage(totalResults, groups);
	}

	private static String directoryPageQuery(String condition) {
		return """
				WITH total AS (
				    SELECT count(*) AS total_results
				    FROM groups g
				    WHERE g.tenant_id = :tenantId
				      AND %1$s
				), page AS (
				    SELECT g.group_id,
				           g.tenant_id,
				           g.display_name,
				           g.status,
				           g.version,
				           g.created_at,
				           g.updated_at
				    FROM groups g
				    WHERE g.tenant_id = :tenantId
				      AND %1$s
				    ORDER BY g.group_id
				    OFFSET :offset
				    LIMIT :limit
				)
				SELECT total.total_results,
				       page.group_id,
				       page.tenant_id,
				       page.display_name,
				       page.status,
				       page.version,
				       page.created_at,
				       page.updated_at
				FROM total
				LEFT JOIN page ON true
				ORDER BY page.group_id
				""".formatted(condition);
	}

	private static String databaseValue(GroupStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case DELETED -> "deleted";
		};
	}

	private static GroupStatus status(String value) {
		return switch (value) {
			case "active" -> GroupStatus.ACTIVE;
			case "deleted" -> GroupStatus.DELETED;
			default -> throw new IllegalStateException("Unsupported group status in the database: " + value);
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("Group write requires an existing read-write transaction");
		}
	}

}
