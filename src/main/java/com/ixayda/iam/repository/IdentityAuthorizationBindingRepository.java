package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.IdentityApplicationAccess;
import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.IdentityAuthorizationSession;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityAuthorizationBindingRepository {

	private final JdbcClient jdbc;

	IdentityAuthorizationBindingRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	/** One SQL snapshot includes the entire original role set. */
	public Optional<IdentityAuthorizationBinding> findById(UUID id) {
		var rows = this.jdbc.sql("""
				SELECT b.*,r.role_id,r.code,r.version AS role_version
				FROM iam_authorization_binding b LEFT JOIN iam_authorization_binding_role r ON r.authorization_id=b.authorization_id
				WHERE b.authorization_id=:id ORDER BY r.code,r.role_id
				""").param("id", id.toString()).query((row, index) -> {
			var roleId = row.getObject("role_id", UUID.class);
			return new BindingRow(row.getObject("user_id", UUID.class), row.getString("client_id"), row.getObject("resource_id", UUID.class), row.getString("audience"),
					row.getLong("credential_version"), row.getLong("client_version"), row.getLong("resource_version"), row.getLong("assignment_version"),
					UUID.fromString(row.getString("browser_session_id")), time(row, "authenticated_at"), time(row, "idle_expires_at"), time(row, "absolute_expires_at"),
					Set.copyOf(Arrays.asList(row.getString("scopes").split(","))), time(row, "issued_at"), time(row, "code_expires_at"),
					roleId == null ? null : new IdentityApplicationAccess.Role(roleId, row.getString("code"), row.getLong("role_version")));
		}).list();
		if (rows.isEmpty()) { return Optional.empty(); }
		var first = rows.getFirst();
		var roles = rows.stream().map(BindingRow::role).filter(java.util.Objects::nonNull).toList();
		var access = new IdentityApplicationAccess(first.userId(), UUID.fromString(first.clientId()), first.resourceId(), first.audience(),
				first.credentialVersion(), first.clientVersion(), first.resourceVersion(), first.assignmentVersion(), roles);
		return Optional.of(new IdentityAuthorizationBinding(id, new IdentityAuthorizationSession(access, first.browserSessionId(), first.authenticatedAt(),
				first.idleExpiresAt(), first.absoluteExpiresAt()), first.scopes(), first.issuedAt(), first.codeExpiresAt()));
	}

	public void insert(IdentityAuthorizationBinding binding) {
		var session = binding.session(); var access = session.access();
		var parameters = new HashMap<String, Object>();
		parameters.put("id", binding.id().toString()); parameters.put("user", access.userId()); parameters.put("client", access.clientId().toString());
		parameters.put("resource", access.resourceId()); parameters.put("audience", access.audience());
		parameters.put("credential", access.credentialVersion()); parameters.put("clientVersion", access.clientVersion());
		parameters.put("resourceVersion", access.resourceVersion()); parameters.put("assignmentVersion", access.assignmentVersion());
		parameters.put("session", session.browserSessionId().toString()); parameters.put("authenticatedAt", timestamp(session.authenticatedAt()));
		parameters.put("idleExpiry", timestamp(session.idleExpiresAt())); parameters.put("absoluteExpiry", timestamp(session.absoluteExpiresAt()));
		parameters.put("scopes", String.join(",", binding.scopes().stream().sorted().toList()));
		parameters.put("issuedAt", timestamp(binding.issuedAt())); parameters.put("codeExpiry", timestamp(binding.codeExpiresAt()));
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_authorization_binding(authorization_id,user_id,client_id,resource_id,audience,
				    credential_version,client_version,resource_version,assignment_version,browser_session_id,
				    authenticated_at,idle_expires_at,absolute_expires_at,scopes,issued_at,code_expires_at)
				VALUES (:id,:user,:client,:resource,:audience,:credential,:clientVersion,:resourceVersion,:assignmentVersion,
				    :session,:authenticatedAt,:idleExpiry,:absoluteExpiry,:scopes,:issuedAt,:codeExpiry)
				""").params(parameters).update());
		for (var role : access.roles()) {
			requireOne(this.jdbc.sql("INSERT INTO iam_authorization_binding_role(authorization_id,resource_id,role_id,code,version) VALUES (:id,:resource,:role,:code,:version)")
					.param("id", binding.id().toString()).param("resource", access.resourceId()).param("role", role.id()).param("code", role.code()).param("version", role.version()).update());
		}
		if (!findById(binding.id()).equals(Optional.of(binding))) { throw new IllegalStateException("Authorization binding was not stored"); }
	}

	public boolean isBeforeDeadline(Instant expiry) {
		return this.jdbc.sql("SELECT clock_timestamp() < :expiry").param("expiry", timestamp(expiry)).query(Boolean.class).single();
	}

	public boolean isWithinLifetime(Instant issued, Instant expiry) {
		return this.jdbc.sql("SELECT :issued <= clock_timestamp() AND clock_timestamp() < :expiry")
				.param("issued", timestamp(issued)).param("expiry", timestamp(expiry)).query(Boolean.class).single();
	}

	private static Instant time(ResultSet row, String column) throws SQLException { return row.getObject(column, OffsetDateTime.class).toInstant(); }
	private static OffsetDateTime timestamp(Instant time) { return OffsetDateTime.ofInstant(time, ZoneOffset.UTC); }
	private static void requireOne(int count) { if (count != 1) { throw new IllegalStateException("Authorization binding was not stored"); } }

	private record BindingRow(UUID userId, String clientId, UUID resourceId, String audience,
			long credentialVersion, long clientVersion, long resourceVersion, long assignmentVersion, UUID browserSessionId,
			Instant authenticatedAt, Instant idleExpiresAt, Instant absoluteExpiresAt, Set<String> scopes, Instant issuedAt, Instant codeExpiresAt, IdentityApplicationAccess.Role role) { }

}
