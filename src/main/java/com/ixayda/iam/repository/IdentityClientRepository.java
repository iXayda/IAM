package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.IdentityClientPage;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Repository;

/** Owns the official protocol store; public reads project no credential or protocol settings. */
@Repository
public class IdentityClientRepository {

	private static final String SELECT = """
			SELECT c.id,c.resource_id,c.status,c.version,c.created_at,c.updated_at,c.secret_rotated_at,
			    r.client_name,r.redirect_uris,r.post_logout_redirect_uris,r.scopes,
			    ARRAY(SELECT a.role_id FROM iam_client_allowed_role a WHERE a.client_id=c.id ORDER BY a.role_id) AS role_ids
			FROM iam_client c JOIN oauth2_registered_client r ON r.id=c.id
			""";
	private final JdbcClient jdbc;
	private final JdbcRegisteredClientRepository registered;

	IdentityClientRepository(JdbcClient jdbc, JdbcTemplate template) {
		this.jdbc = jdbc;
		this.registered = new JdbcRegisteredClientRepository(template);
	}

	public Optional<IdentityClient> findById(UUID id) {
		return this.jdbc.sql(SELECT + " WHERE c.id=:id").param("id", id.toString()).query(IdentityClientRepository::mapClient).optional();
	}

	/** Parent resources and referenced roles must already be locked by the workflow. */
	public Optional<IdentityClient> lockById(UUID id) {
		return this.jdbc.sql(SELECT + " WHERE c.id=:id FOR UPDATE OF c,r").param("id", id.toString()).query(IdentityClientRepository::mapClient).optional();
	}

	/** Trusted protocol/configuration access only; never returned by a public client query. */
	public RegisteredClient registeredById(UUID id) { return this.registered.findById(id.toString()); }

	public Instant databaseTime() {
		return this.jdbc.sql("SELECT clock_timestamp()").query((row, index) -> row.getObject(1, OffsetDateTime.class).toInstant()).single();
	}

	public IdentityClient create(RegisteredClient client, UUID resourceId, Set<UUID> roleIds) {
		saveRegistered(client);
		var time = OffsetDateTime.ofInstant(client.getClientIdIssuedAt(), ZoneOffset.UTC);
		requireOne(this.jdbc.sql("INSERT INTO iam_client(id,resource_id,created_at,updated_at,secret_rotated_at) VALUES (:id,:resource,:time,:time,:time)")
				.param("id", client.getId()).param("resource", resourceId).param("time", time).update());
		insertRoles(client.getId(), resourceId, roleIds);
		var expected = new IdentityClient(UUID.fromString(client.getId()), configuration(client, resourceId, roleIds), IdentityClient.Status.ACTIVE, 1,
				client.getClientIdIssuedAt(), client.getClientIdIssuedAt(), client.getClientIdIssuedAt());
		return requireStored(expected);
	}

	public IdentityClient update(IdentityClient previous, RegisteredClient client, UUID resourceId, Set<UUID> roleIds,
			IdentityClient.Status status, boolean rotateSecret) {
		boolean rolesChanged = !previous.configuration().resourceId().equals(resourceId) || !previous.configuration().allowedRoleIds().equals(roleIds);
		if (rolesChanged) { this.jdbc.sql("DELETE FROM iam_client_allowed_role WHERE client_id=:id").param("id", client.getId()).update(); }
		saveRegistered(client);
		Instant now = databaseTime();
		Instant rotated = rotateSecret ? now : previous.secretRotatedAt();
		long next = Math.addExact(previous.version(), 1);
		requireOne(this.jdbc.sql("""
				UPDATE iam_client SET resource_id=:resource,status=:status,version=:next,updated_at=:now,secret_rotated_at=:rotated
				WHERE id=:id AND version=:version
				""").param("resource", resourceId).param("status", status.name().toLowerCase(Locale.ROOT)).param("next", next)
				.param("now", OffsetDateTime.ofInstant(now, ZoneOffset.UTC)).param("rotated", OffsetDateTime.ofInstant(rotated, ZoneOffset.UTC))
				.param("id", client.getId()).param("version", previous.version()).update());
		if (rolesChanged) { insertRoles(client.getId(), resourceId, roleIds); }
		return requireStored(new IdentityClient(previous.id(), configuration(client, resourceId, roleIds), status, next, previous.createdAt(), now, rotated));
	}

	public List<IdentityClient> search(IdentityClient.Status status, int limit, IdentityClientPage.Cursor after) {
		var parameters = new HashMap<String, Object>();
		var conditions = new StringBuilder(" WHERE true");
		if (status != null) { conditions.append(" AND c.status=:status"); parameters.put("status", status.name().toLowerCase(Locale.ROOT)); }
		if (after != null) {
			conditions.append(" AND (c.created_at,c.id) > (:time,:id)");
			parameters.put("time", OffsetDateTime.ofInstant(after.createdAt(), ZoneOffset.UTC));
			parameters.put("id", after.id().toString());
		}
		parameters.put("limit", limit);
		return this.jdbc.sql(SELECT + conditions + " ORDER BY c.created_at,c.id LIMIT :limit").params(parameters).query(IdentityClientRepository::mapClient).list();
	}

	private void saveRegistered(RegisteredClient expected) {
		this.registered.save(expected);
		if (!expected.equals(this.registered.findById(expected.getId()))) { throw new IllegalStateException("Protocol client was not stored"); }
	}

	private IdentityClient requireStored(IdentityClient expected) {
		var stored = findById(expected.id()).orElseThrow(() -> new IllegalStateException("Client was not stored"));
		if (!expected.equals(stored)) { throw new IllegalStateException("Client was not stored"); }
		return stored;
	}

	private void insertRoles(String id, UUID resourceId, Set<UUID> roleIds) {
		for (UUID roleId : roleIds.stream().sorted().toList()) {
			requireOne(this.jdbc.sql("INSERT INTO iam_client_allowed_role(client_id,resource_id,role_id) VALUES (:client,:resource,:role)")
					.param("client", id).param("resource", resourceId).param("role", roleId).update());
		}
	}

	private static IdentityClientConfiguration configuration(RegisteredClient client, UUID resourceId, Set<UUID> roleIds) {
		return new IdentityClientConfiguration(client.getClientName(), resourceId, client.getRedirectUris().stream().sorted().toList(), client.getScopes(), roleIds);
	}

	private static IdentityClient mapClient(ResultSet row, int index) throws SQLException {
		var roleIds = Arrays.stream((Object[]) row.getArray("role_ids").getArray()).map(value -> UUID.fromString(value.toString())).collect(Collectors.toUnmodifiableSet());
		var config = new IdentityClientConfiguration(row.getString("client_name"), row.getObject("resource_id", UUID.class),
				split(row.getString("redirect_uris")), Set.copyOf(split(row.getString("scopes"))), roleIds);
		return new IdentityClient(UUID.fromString(row.getString("id")), config, IdentityClient.Status.valueOf(row.getString("status").toUpperCase(Locale.ROOT)),
				row.getLong("version"), row.getObject("created_at", OffsetDateTime.class).toInstant(), row.getObject("updated_at", OffsetDateTime.class).toInstant(),
				row.getObject("secret_rotated_at", OffsetDateTime.class).toInstant());
	}

	private static List<String> split(String value) { return value == null || value.isEmpty() ? List.of() : Arrays.stream(value.split(",", -1)).sorted().toList(); }
	private static void requireOne(int changed) { if (changed != 1) { throw new IllegalStateException("Client mutation was not stored"); } }

}
