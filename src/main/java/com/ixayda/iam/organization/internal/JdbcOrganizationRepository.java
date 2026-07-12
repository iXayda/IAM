package com.ixayda.iam.organization.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.organization.Organization;
import com.ixayda.iam.organization.OrganizationAlreadyExistsException;
import com.ixayda.iam.organization.OrganizationConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationStatus;
import com.ixayda.iam.tenant.TenantId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class JdbcOrganizationRepository {

	private static final String COLUMNS =
			"organization_id, tenant_id, slug, display_name, status, version, created_at, updated_at";

	private static final RowMapper<Organization> ORGANIZATION_ROW_MAPPER = JdbcOrganizationRepository::mapOrganization;

	private final JdbcClient jdbcClient;

	JdbcOrganizationRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	Organization insert(Organization organization) {
		Objects.requireNonNull(organization, "Organization must not be null");
		int affected = this.jdbcClient.sql("""
				INSERT INTO organizations
				    (organization_id, tenant_id, slug, display_name, status, version, created_at, updated_at)
				VALUES
				    (:organizationId, :tenantId, :slug, :displayName, :status, :version, :createdAt, :updatedAt)
				ON CONFLICT (tenant_id, slug) DO NOTHING
				""")
			.param("organizationId", organization.id().value())
			.param("tenantId", organization.tenantId().value())
			.param("slug", organization.slug())
			.param("displayName", organization.displayName())
			.param("status", databaseValue(organization.status()))
			.param("version", organization.version())
			.param("createdAt", databaseValue(organization.createdAt()))
			.param("updatedAt", databaseValue(organization.updatedAt()))
			.update();
		if (affected == 0) {
			throw new OrganizationAlreadyExistsException(organization.tenantId(), organization.slug());
		}
		if (affected != 1) {
			throw new IllegalStateException("Creating an organization affected an unexpected number of rows: " + affected);
		}
		return organization;
	}

	Optional<Organization> findById(TenantId tenantId, OrganizationId organizationId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(organizationId, "Organization ID must not be null");
		return this.jdbcClient
			.sql("SELECT " + COLUMNS
					+ " FROM organizations WHERE tenant_id = :tenantId AND organization_id = :organizationId")
			.param("tenantId", tenantId.value())
			.param("organizationId", organizationId.value())
			.query(ORGANIZATION_ROW_MAPPER)
			.optional();
	}

	Optional<Organization> findBySlug(TenantId tenantId, String slug) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(slug, "Organization slug must not be null");
		return this.jdbcClient
			.sql("SELECT " + COLUMNS + " FROM organizations WHERE tenant_id = :tenantId AND slug = :slug")
			.param("tenantId", tenantId.value())
			.param("slug", slug)
			.query(ORGANIZATION_ROW_MAPPER)
			.optional();
	}

	Organization updateStatus(Organization current, Organization changed) {
		if (!current.id().equals(changed.id()) || !current.tenantId().equals(changed.tenantId())
				|| !current.slug().equals(changed.slug()) || !current.displayName().equals(changed.displayName())
				|| !current.createdAt().equals(changed.createdAt()) || current.status() == changed.status()
				|| changed.version() != current.version() + 1 || changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Organization status update must preserve ownership and identity, and advance one version to a different status");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE organizations
				SET status = :newStatus, version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND version = :expectedVersion
				  AND status = :expectedStatus
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("organizationId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new OrganizationConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating an organization affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private static Organization mapOrganization(ResultSet resultSet, int rowNumber) throws SQLException {
		return new Organization(new OrganizationId(resultSet.getObject("organization_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)), resultSet.getString("slug"),
				resultSet.getString("display_name"), status(resultSet.getString("status")),
				resultSet.getLong("version"), resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

	private static String databaseValue(OrganizationStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case DISABLED -> "disabled";
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static OrganizationStatus status(String value) {
		return switch (value) {
			case "active" -> OrganizationStatus.ACTIVE;
			case "disabled" -> OrganizationStatus.DISABLED;
			default -> throw new IllegalStateException("Unsupported organization status in the database: " + value);
		};
	}

}
