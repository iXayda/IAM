package com.ixayda.iam.tenant.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantAlreadyExistsException;
import com.ixayda.iam.tenant.TenantConcurrentUpdateException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantStatus;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class JdbcTenantRepository {

	private static final String COLUMNS = "tenant_id, slug, display_name, status, version, created_at, updated_at";

	private static final RowMapper<Tenant> TENANT_ROW_MAPPER = JdbcTenantRepository::mapTenant;

	private final JdbcClient jdbcClient;

	JdbcTenantRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	Tenant insert(Tenant tenant) {
		int affected = this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name, status, version, created_at, updated_at)
				VALUES (:tenantId, :slug, :displayName, :status, :version, :createdAt, :updatedAt)
				ON CONFLICT (slug) DO NOTHING
				""")
			.param("tenantId", tenant.id().value())
			.param("slug", tenant.slug())
			.param("displayName", tenant.displayName())
			.param("status", databaseValue(tenant.status()))
			.param("version", tenant.version())
			.param("createdAt", databaseValue(tenant.createdAt()))
			.param("updatedAt", databaseValue(tenant.updatedAt()))
			.update();
		if (affected == 0) {
			throw new TenantAlreadyExistsException(tenant.slug());
		}
		if (affected != 1) {
			throw new IllegalStateException("Creating a tenant affected an unexpected number of rows: " + affected);
		}
		return tenant;
	}

	Optional<Tenant> findById(TenantId tenantId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS + " FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.query(TENANT_ROW_MAPPER)
			.optional();
	}

	Optional<Tenant> findBySlug(String slug) {
		Objects.requireNonNull(slug, "Tenant slug must not be null");
		return this.jdbcClient.sql("SELECT " + COLUMNS + " FROM tenants WHERE slug = :slug")
			.param("slug", slug)
			.query(TENANT_ROW_MAPPER)
			.optional();
	}

	Tenant updateStatus(Tenant current, Tenant changed) {
		if (!current.id().equals(changed.id()) || !current.slug().equals(changed.slug())
				|| !current.displayName().equals(changed.displayName())
				|| !current.createdAt().equals(changed.createdAt()) || current.status() == changed.status()
				|| changed.version() != current.version() + 1) {
			throw new IllegalArgumentException(
					"Tenant status update must preserve identity and advance one version to a different status");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE tenants
				SET status = :newStatus, version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId AND version = :expectedVersion AND status = :expectedStatus
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new TenantConcurrentUpdateException(current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating a tenant affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	private static Tenant mapTenant(ResultSet resultSet, int rowNumber) throws SQLException {
		return new Tenant(new TenantId(resultSet.getObject("tenant_id", UUID.class)), resultSet.getString("slug"),
				resultSet.getString("display_name"), status(resultSet.getString("status")), resultSet.getLong("version"),
				resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

	private static String databaseValue(TenantStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case DISABLED -> "disabled";
		};
	}

	private static OffsetDateTime databaseValue(java.time.Instant instant) {
		return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static TenantStatus status(String value) {
		return switch (value) {
			case "active" -> TenantStatus.ACTIVE;
			case "disabled" -> TenantStatus.DISABLED;
			default -> throw new IllegalStateException("Unsupported tenant status in the database: " + value);
		};
	}

}
