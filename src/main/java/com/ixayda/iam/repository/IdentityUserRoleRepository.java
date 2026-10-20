package com.ixayda.iam.repository;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityApplicationAccess;
import com.ixayda.iam.model.IdentityUserRole;
import com.ixayda.iam.model.IdentityUserRolePage;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityUserRoleRepository {

	private final JdbcClient jdbc;

	IdentityUserRoleRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public long version(UUID userId, UUID resourceId) {
		return this.jdbc.sql("SELECT version FROM iam_user_resource_role_revision WHERE user_id=:user AND resource_id=:resource")
				.param("user", userId).param("resource", resourceId).query(Long.class).optional().orElse(0L);
	}

	public Optional<IdentityUserRole> find(UUID userId, UUID roleId) {
		return this.jdbc.sql("SELECT user_id,resource_id,role_id,created_at FROM iam_user_role WHERE user_id=:user AND role_id=:role")
				.param("user", userId).param("role", roleId).query((row, index) -> new IdentityUserRole(row.getObject("user_id", UUID.class),
						row.getObject("resource_id", UUID.class), row.getObject("role_id", UUID.class), row.getObject("created_at", OffsetDateTime.class).toInstant())).optional();
	}

	/** The caller already holds the user, parent resource and role locks. */
	public long advanceVersion(UUID userId, UUID resourceId, long expectedVersion) {
		long next = Math.addExact(expectedVersion, 1);
		int changed = this.jdbc.sql("""
				INSERT INTO iam_user_resource_role_revision(user_id,resource_id,version) VALUES (:user,:resource,1)
				ON CONFLICT (user_id,resource_id) DO UPDATE
				SET version=iam_user_resource_role_revision.version+1, updated_at=clock_timestamp()
				WHERE iam_user_resource_role_revision.version=:expected
				""").param("user", userId).param("resource", resourceId).param("expected", expectedVersion).update();
		if (changed != 1 || version(userId, resourceId) != next) { throw new IllegalStateException("Assignment revision was not stored"); }
		return next;
	}

	public void grant(UUID userId, UUID resourceId, UUID roleId) {
		int inserted = this.jdbc.sql("INSERT INTO iam_user_role(user_id,resource_id,role_id) VALUES (:user,:resource,:role)")
				.param("user", userId).param("resource", resourceId).param("role", roleId).update();
		var stored = find(userId, roleId).orElseThrow(() -> new IllegalStateException("Role assignment was not stored"));
		if (inserted != 1 || !resourceId.equals(stored.resourceId())) { throw new IllegalStateException("Role assignment was not stored"); }
	}

	public void revoke(UUID userId, UUID roleId) {
		int deleted = this.jdbc.sql("DELETE FROM iam_user_role WHERE user_id=:user AND role_id=:role")
				.param("user", userId).param("role", roleId).update();
		if (deleted != 1 || find(userId, roleId).isPresent()) { throw new IllegalStateException("Role assignment was not revoked"); }
	}

	/** One statement binds the visible assignment revision to the exact page snapshot. */
	public PageSnapshot search(UUID userId, UUID resourceId, int limit, IdentityUserRolePage.Cursor after) {
		var parameters = new HashMap<String, Object>();
		parameters.put("user", userId);
		parameters.put("resource", resourceId);
		parameters.put("limit", limit);
		String position = "";
		if (after != null) {
			position = " AND (created_at,role_id) > (:time,:role)";
			parameters.put("time", OffsetDateTime.ofInstant(after.createdAt(), ZoneOffset.UTC));
			parameters.put("role", after.roleId());
		}
		var rows = this.jdbc.sql("""
				WITH revision AS (
				    SELECT coalesce((SELECT version FROM iam_user_resource_role_revision WHERE user_id=:user AND resource_id=:resource),0) AS version
				), page AS (
				    SELECT role_id,created_at FROM iam_user_role WHERE user_id=:user AND resource_id=:resource
				""" + position + " ORDER BY created_at,role_id LIMIT :limit) " + """
				SELECT revision.version,page.role_id,page.created_at FROM revision LEFT JOIN page ON true
				ORDER BY page.created_at,page.role_id
				""").params(parameters).query((row, index) -> new SnapshotRow(row.getLong("version"), row.getObject("role_id", UUID.class),
						row.getObject("created_at", OffsetDateTime.class))).list();
		var items = new ArrayList<IdentityUserRole>();
		for (var row : rows) {
			if (row.roleId() != null) { items.add(new IdentityUserRole(userId, resourceId, row.roleId(), row.createdAt().toInstant())); }
		}
		return new PageSnapshot(rows.getFirst().version(), List.copyOf(items));
	}

	/** One statement captures the revision and all matching roles; pagination never truncates authorization. */
	public RoleProjection projectForClient(UUID userId, UUID resourceId, UUID clientId) {
		var rows = this.jdbc.sql("""
				WITH revision AS (
				    SELECT coalesce((SELECT version FROM iam_user_resource_role_revision WHERE user_id=:user AND resource_id=:resource),0) AS version
				), permitted AS (
				    SELECT r.id,r.code,r.version FROM iam_user_role b
				    JOIN iam_resource_role r ON r.id=b.role_id AND r.resource_id=b.resource_id AND r.status='active'
				    JOIN iam_client_allowed_role a ON a.role_id=b.role_id AND a.resource_id=b.resource_id
				    JOIN iam_client c ON c.id=a.client_id AND c.resource_id=b.resource_id AND c.status='active'
				    JOIN iam_resource p ON p.id=b.resource_id AND p.status='active'
				    JOIN iam_user u ON u.id=b.user_id AND u.status='active'
				    WHERE b.user_id=:user AND b.resource_id=:resource AND c.id=:client
				)
				SELECT revision.version,permitted.id AS role_id,permitted.code,permitted.version AS role_version
				FROM revision LEFT JOIN permitted ON true ORDER BY permitted.code,permitted.id
				""").param("user", userId).param("resource", resourceId).param("client", clientId.toString())
				.query((row, index) -> new ProjectionRow(row.getLong("version"), row.getObject("role_id", UUID.class), row.getString("code"), row.getLong("role_version"))).list();
		var roles = rows.stream().filter(row -> row.roleId() != null).map(row -> new IdentityApplicationAccess.Role(row.roleId(), row.code(), row.roleVersion())).toList();
		return new RoleProjection(rows.getFirst().version(), roles);
	}

	public record PageSnapshot(long version, List<IdentityUserRole> items) { }
	public record RoleProjection(long version, List<IdentityApplicationAccess.Role> roles) { }
	private record SnapshotRow(long version, UUID roleId, OffsetDateTime createdAt) { }
	private record ProjectionRow(long version, UUID roleId, String code, long roleVersion) { }

}
