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
import com.ixayda.iam.model.IdentityResource;

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
	private static final String PROTOCOL_SELECT = """
			SELECT r.id,r.client_id,r.client_id_issued_at,r.client_secret,r.client_secret_expires_at,r.client_name,
			    r.client_authentication_methods,r.authorization_grant_types,r.redirect_uris,r.post_logout_redirect_uris,
			    r.scopes,r.client_settings,r.token_settings,c.resource_id,c.status,c.version,c.created_at,c.updated_at,c.secret_rotated_at,
			    p.audience AS resource_audience,p.display_name AS resource_display_name,p.status AS resource_status,
			    p.version AS resource_version,p.created_at AS resource_created_at,p.updated_at AS resource_updated_at,
			    ARRAY(SELECT a.role_id FROM iam_client_allowed_role a WHERE a.client_id=c.id ORDER BY a.role_id) AS role_ids
			FROM iam_client c JOIN oauth2_registered_client r ON r.id=c.id JOIN iam_resource p ON p.id=c.resource_id
			WHERE c.id=:id AND c.status='active' AND p.status='active'
			""";
	private final JdbcClient jdbc;
	private final JdbcRegisteredClientRepository registered;
	private final JdbcRegisteredClientRepository.JsonMapperRegisteredClientRowMapper protocolMapper = new JdbcRegisteredClientRepository.JsonMapperRegisteredClientRowMapper();

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

	/** One statement captures native registration, public configuration and resource epochs together. */
	public Optional<StoredProtocolClient> findActiveProtocolClient(UUID id) {
		return this.jdbc.sql(PROTOCOL_SELECT).param("id", id.toString()).query((row, index) -> {
			var resource = new IdentityResource(row.getObject("resource_id", UUID.class), row.getString("resource_audience"), row.getString("resource_display_name"),
					IdentityResource.Status.valueOf(row.getString("resource_status").toUpperCase(Locale.ROOT)), row.getLong("resource_version"),
					row.getObject("resource_created_at", OffsetDateTime.class).toInstant(), row.getObject("resource_updated_at", OffsetDateTime.class).toInstant());
			return new StoredProtocolClient(this.protocolMapper.mapRow(row, index), mapClient(row, index), resource);
		}).optional();
	}

	public boolean isWritableReadCommittedTransaction() {
		return this.jdbc.sql("SELECT current_setting('transaction_isolation')='read committed' AND current_setting('transaction_read_only')='off'").query(Boolean.class).single();
	}

	/** Caller has locked signing keys and subjects before resource -> roles -> client ordering. */
	public boolean lockProtocolResource(UUID id) {
		return this.jdbc.sql("SELECT id FROM iam_resource WHERE id=:id FOR SHARE").param("id", id).query(UUID.class).optional().isPresent();
	}

	public boolean lockProtocolRoles(UUID resourceId, Set<UUID> roleIds) {
		if (roleIds.isEmpty()) { return true; }
		return this.jdbc.sql("SELECT id FROM iam_resource_role WHERE resource_id=:resource AND id IN (:roles) ORDER BY id FOR SHARE")
				.param("resource", resourceId).param("roles", roleIds.stream().sorted().toList()).query(UUID.class).list().size() == roleIds.size();
	}

	/** A fresh protocol snapshot must be read after this statement completes any lock waits. */
	public boolean lockProtocolClient(UUID id) {
		return this.jdbc.sql("SELECT c.id FROM iam_client c JOIN oauth2_registered_client r ON r.id=c.id WHERE c.id=:id FOR SHARE OF c,r")
				.param("id", id.toString()).query(String.class).optional().isPresent();
	}

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

	public record StoredProtocolClient(RegisteredClient registration, IdentityClient client, IdentityResource resource) {
		@Override
		public String toString() { return "StoredProtocolClient[REDACTED]"; }
	}

}
