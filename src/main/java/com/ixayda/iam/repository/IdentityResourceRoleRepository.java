package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResourceRole;
import com.ixayda.iam.model.IdentityResourceRolePage;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityResourceRoleRepository {

	private static final String COLUMNS = "id, resource_id, code, display_name, status, version, created_at, updated_at";
	private final JdbcClient jdbc;

	IdentityResourceRoleRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Optional<IdentityResourceRole> findById(UUID id) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM iam_resource_role WHERE id = :id")
				.param("id", id).query(IdentityResourceRoleRepository::mapRole).optional();
	}

	public Optional<IdentityResourceRole> findByCode(UUID resourceId, String code) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM iam_resource_role WHERE resource_id = :resource AND code = :code")
				.param("resource", resourceId).param("code", code).query(IdentityResourceRoleRepository::mapRole).optional();
	}

	public Optional<IdentityResourceRole> lockById(UUID id) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM iam_resource_role WHERE id = :id FOR UPDATE")
				.param("id", id).query(IdentityResourceRoleRepository::mapRole).optional();
	}

	public IdentityResourceRole create(UUID id, UUID resourceId, String code, String displayName) {
		int inserted = this.jdbc.sql("INSERT INTO iam_resource_role (id, resource_id, code, display_name) VALUES (:id, :resource, :code, :display)")
				.param("id", id).param("resource", resourceId).param("code", code).param("display", displayName).update();
		var stored = findById(id).orElseThrow(() -> new IllegalStateException("Resource role was not stored"));
		if (inserted != 1 || !resourceId.equals(stored.resourceId()) || !code.equals(stored.code()) || !displayName.equals(stored.displayName())
				|| stored.status() != IdentityResourceRole.Status.ACTIVE || stored.version() != 1) {
			throw new IllegalStateException("Resource role was not stored");
		}
		return stored;
	}

	/** The caller owns the parent resource and role locks. */
	public IdentityResourceRole update(IdentityResourceRole previous, String displayName, IdentityResourceRole.Status status) {
		long next = Math.addExact(previous.version(), 1);
		int changed = this.jdbc.sql("""
				UPDATE iam_resource_role SET display_name = :display, status = :status, version = :next, updated_at = clock_timestamp()
				WHERE id = :id AND version = :version
				""").param("display", displayName).param("status", status.name().toLowerCase(Locale.ROOT)).param("next", next)
				.param("id", previous.id()).param("version", previous.version()).update();
		var stored = findById(previous.id()).orElseThrow(() -> new IllegalStateException("Resource role was not stored"));
		if (changed != 1 || stored.version() != next || !displayName.equals(stored.displayName()) || status != stored.status()
				|| !previous.resourceId().equals(stored.resourceId()) || !previous.code().equals(stored.code()) || !previous.createdAt().equals(stored.createdAt())) {
			throw new IllegalStateException("Resource role was not stored");
		}
		return stored;
	}

	public List<IdentityResourceRole> search(UUID resourceId, IdentityResourceRole.Status status, int limit, IdentityResourceRolePage.Cursor after) {
		var sql = new StringBuilder("SELECT " + COLUMNS + " FROM iam_resource_role WHERE resource_id = :resource");
		var parameters = new HashMap<String, Object>();
		parameters.put("resource", resourceId);
		if (status != null) {
			sql.append(" AND status = :status");
			parameters.put("status", status.name().toLowerCase(Locale.ROOT));
		}
		if (after != null) {
			sql.append(" AND (created_at, id) > (:time, :id)");
			parameters.put("time", OffsetDateTime.ofInstant(after.createdAt(), ZoneOffset.UTC));
			parameters.put("id", after.id());
		}
		parameters.put("limit", limit);
		return this.jdbc.sql(sql.append(" ORDER BY created_at, id LIMIT :limit").toString()).params(parameters)
				.query(IdentityResourceRoleRepository::mapRole).list();
	}

	private static IdentityResourceRole mapRole(ResultSet row, int index) throws SQLException {
		return new IdentityResourceRole(row.getObject("id", UUID.class), row.getObject("resource_id", UUID.class), row.getString("code"), row.getString("display_name"),
				IdentityResourceRole.Status.valueOf(row.getString("status").toUpperCase(Locale.ROOT)), row.getLong("version"),
				row.getObject("created_at", OffsetDateTime.class).toInstant(), row.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

}
