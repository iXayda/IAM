package com.ixayda.iam.organization.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationMembership;
import com.ixayda.iam.organization.OrganizationMembershipConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationMembershipStatus;
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
class JdbcOrganizationMembershipRepository {

	private static final String COLUMNS =
			"tenant_id, organization_id, user_id, status, version, created_at, updated_at";

	private static final RowMapper<OrganizationMembership> ROW_MAPPER =
			JdbcOrganizationMembershipRepository::mapMembership;

	private final JdbcClient jdbcClient;

	JdbcOrganizationMembershipRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = OrganizationMembershipAlreadyExistsException.class)
	OrganizationMembership insert(OrganizationMembership membership) {
		Objects.requireNonNull(membership, "Organization membership must not be null");
		requireWriteTransaction();
		if (membership.status() != OrganizationMembershipStatus.ACTIVE || membership.version() != 0
				|| !membership.createdAt().equals(membership.updatedAt())) {
			throw new IllegalArgumentException(
					"New organization membership must be active at version zero and start at its creation time");
		}

		int affected = this.jdbcClient.sql("""
				INSERT INTO organization_memberships
				    (tenant_id, organization_id, user_id, status, version, created_at, updated_at)
				VALUES
				    (:tenantId, :organizationId, :userId, :status, :version, :createdAt, :updatedAt)
				ON CONFLICT (tenant_id, organization_id, user_id) DO NOTHING
				""")
			.param("tenantId", membership.tenantId().value())
			.param("organizationId", membership.organizationId().value())
			.param("userId", membership.userId().value())
			.param("status", databaseValue(membership.status()))
			.param("version", membership.version())
			.param("createdAt", databaseValue(membership.createdAt()))
			.param("updatedAt", databaseValue(membership.updatedAt()))
			.update();
		if (affected == 0) {
			throw new OrganizationMembershipAlreadyExistsException(membership.tenantId(),
					membership.organizationId(), membership.userId());
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Creating an organization membership affected an unexpected number of rows: " + affected);
		}
		return membership;
	}

	Optional<OrganizationMembership> find(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(organizationId, "Organization ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS
				+ " FROM organization_memberships WHERE tenant_id = :tenantId"
				+ " AND organization_id = :organizationId AND user_id = :userId")
			.param("tenantId", tenantId.value())
			.param("organizationId", organizationId.value())
			.param("userId", userId.value())
			.query(ROW_MAPPER)
			.optional();
	}

	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = OrganizationMembershipConcurrentUpdateException.class)
	OrganizationMembership update(OrganizationMembership current, OrganizationMembership changed) {
		Objects.requireNonNull(current, "Current organization membership must not be null");
		Objects.requireNonNull(changed, "Changed organization membership must not be null");
		requireWriteTransaction();
		if (!current.tenantId().equals(changed.tenantId())
				|| !current.organizationId().equals(changed.organizationId())
				|| !current.userId().equals(changed.userId()) || !current.createdAt().equals(changed.createdAt())
				|| current.status() == changed.status() || current.version() == Long.MAX_VALUE
				|| changed.version() != current.version() + 1 || changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Organization membership update must preserve identity and creation time, change status, and advance one version");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE organization_memberships
				SET status = :newStatus,
				    version = :newVersion,
				    updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND user_id = :userId
				  AND status = :expectedStatus
				  AND version = :expectedVersion
				  AND created_at = :expectedCreatedAt
				  AND updated_at = :expectedUpdatedAt
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("organizationId", current.organizationId().value())
			.param("userId", current.userId().value())
			.param("expectedStatus", databaseValue(current.status()))
			.param("expectedVersion", current.version())
			.param("expectedCreatedAt", databaseValue(current.createdAt()))
			.param("expectedUpdatedAt", databaseValue(current.updatedAt()))
			.update();
		if (affected == 0) {
			throw new OrganizationMembershipConcurrentUpdateException(current.tenantId(), current.organizationId(),
					current.userId(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException(
					"Updating an organization membership affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private static OrganizationMembership mapMembership(ResultSet resultSet, int rowNumber) throws SQLException {
		return new OrganizationMembership(new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new OrganizationId(resultSet.getObject("organization_id", UUID.class)),
				new UserId(resultSet.getObject("user_id", UUID.class)), status(resultSet.getString("status")),
				resultSet.getLong("version"), resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

	private static String databaseValue(OrganizationMembershipStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case REMOVED -> "removed";
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static OrganizationMembershipStatus status(String value) {
		return switch (value) {
			case "active" -> OrganizationMembershipStatus.ACTIVE;
			case "removed" -> OrganizationMembershipStatus.REMOVED;
			default -> throw new IllegalStateException("Unsupported organization membership status in the database: "
					+ value);
		};
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException(
					"Organization membership write requires an existing read-write transaction");
		}
	}

}
