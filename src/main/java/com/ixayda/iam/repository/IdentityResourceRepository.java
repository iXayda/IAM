package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourcePage;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityResourceRepository {

	private static final String COLUMNS = "id, audience, display_name, status, version, created_at, updated_at";
	private final JdbcClient jdbc;

	IdentityResourceRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Optional<IdentityResource> findById(UUID id) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM iam_resource WHERE id = :id")
				.param("id", id).query(IdentityResourceRepository::mapResource).optional();
	}

	public Optional<IdentityResource> findByAudience(String audience) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM iam_resource WHERE audience = :audience")
				.param("audience", audience).query(IdentityResourceRepository::mapResource).optional();
	}

	public Optional<IdentityResource> lockById(UUID id) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM iam_resource WHERE id = :id FOR UPDATE")
				.param("id", id).query(IdentityResourceRepository::mapResource).optional();
	}

	public IdentityResource create(UUID id, String audience, String displayName) {
		int inserted = this.jdbc.sql("INSERT INTO iam_resource (id, audience, display_name) VALUES (:id, :audience, :display)")
				.param("id", id).param("audience", audience).param("display", displayName).update();
		var stored = findById(id).orElseThrow(() -> new IllegalStateException("Resource was not stored"));
		if (inserted != 1 || !audience.equals(stored.audience()) || !displayName.equals(stored.displayName())
				|| stored.status() != IdentityResource.Status.ACTIVE || stored.version() != 1) {
			throw new IllegalStateException("Resource was not stored");
		}
		return stored;
	}

	/** The caller owns the row lock and supplies the current version. */
	public IdentityResource update(IdentityResource previous, String displayName, IdentityResource.Status status) {
		long next = Math.addExact(previous.version(), 1);
		int updated = this.jdbc.sql("""
				UPDATE iam_resource SET display_name = :display, status = :status,
				    version = :next, updated_at = clock_timestamp()
				WHERE id = :id AND version = :version
				""").param("display", displayName).param("status", status.name().toLowerCase(Locale.ROOT))
				.param("id", previous.id()).param("version", previous.version()).param("next", next).update();
		var stored = findById(previous.id()).orElseThrow(() -> new IllegalStateException("Resource was not stored"));
		if (updated != 1 || stored.version() != next || !displayName.equals(stored.displayName()) || status != stored.status()
				|| !previous.audience().equals(stored.audience()) || !previous.createdAt().equals(stored.createdAt())) {
			throw new IllegalStateException("Resource was not stored");
		}
		return stored;
	}

	public List<IdentityResource> search(IdentityResource.Status status, int limit, IdentityResourcePage.Cursor after) {
		var sql = new StringBuilder("SELECT " + COLUMNS + " FROM iam_resource WHERE 1 = 1");
		var parameters = new HashMap<String, Object>();
		if (status != null) {
			sql.append(" AND status = :status");
			parameters.put("status", status.name().toLowerCase(Locale.ROOT));
		}
		if (after != null) {
			sql.append(" AND (created_at, id) > (:time, :id)");
			parameters.put("time", OffsetDateTime.ofInstant(after.createdAt(), java.time.ZoneOffset.UTC));
			parameters.put("id", after.id());
		}
		sql.append(" ORDER BY created_at, id LIMIT :limit");
		parameters.put("limit", limit);
		return this.jdbc.sql(sql.toString()).params(parameters).query(IdentityResourceRepository::mapResource).list();
	}

	private static IdentityResource mapResource(ResultSet row, int index) throws SQLException {
		return new IdentityResource(row.getObject("id", UUID.class), row.getString("audience"), row.getString("display_name"),
				IdentityResource.Status.valueOf(row.getString("status").toUpperCase(Locale.ROOT)), row.getLong("version"),
				row.getObject("created_at", OffsetDateTime.class).toInstant(), row.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

}
