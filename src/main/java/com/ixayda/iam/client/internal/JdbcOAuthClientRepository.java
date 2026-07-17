package com.ixayda.iam.client.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.client.ClientAlreadyExistsException;
import com.ixayda.iam.client.ClientAuthenticationMethod;
import com.ixayda.iam.client.ClientConcurrentUpdateException;
import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientRedirectUri;
import com.ixayda.iam.client.ClientScope;
import com.ixayda.iam.client.ClientSecretMetadata;
import com.ixayda.iam.client.ClientStatus;
import com.ixayda.iam.client.ClientTokenPolicy;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.tenant.TenantId;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
class JdbcOAuthClientRepository {

	private static final String CLIENT_COLUMNS = """
			client_id, tenant_id, client_identifier, display_name, client_type,
			authentication_method, status, encoded_client_secret, client_secret_issued_at,
			client_secret_expires_at, authorization_code_ttl_seconds,
			access_token_ttl_seconds, refresh_tokens_enabled, refresh_token_ttl_seconds,
			version, created_at, updated_at
			""";

	private static final RowMapper<ClientRow> CLIENT_ROW_MAPPER = JdbcOAuthClientRepository::mapClientRow;

	private final JdbcClient jdbcClient;

	JdbcOAuthClientRepository(JdbcClient jdbcClient) {
		this.jdbcClient = jdbcClient;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	StoredOAuthClient insert(StoredOAuthClient stored) {
		Objects.requireNonNull(stored, "Stored OAuth client must not be null");
		requireWriteTransaction();
		OAuthClient client = stored.client();
		int affected = this.jdbcClient.sql("""
				INSERT INTO oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type,
				     authentication_method, status, encoded_client_secret,
				     client_secret_issued_at, client_secret_expires_at,
				     authorization_code_ttl_seconds, access_token_ttl_seconds,
				     refresh_tokens_enabled, refresh_token_ttl_seconds,
				     version, created_at, updated_at)
				VALUES
				    (:clientId, :tenantId, :identifier, :displayName, :clientType,
				     :authenticationMethod, :status, :encodedSecret,
				     CAST(:secretIssuedAt AS timestamptz), CAST(:secretExpiresAt AS timestamptz),
				     :authorizationCodeTtl, :accessTokenTtl, :refreshTokensEnabled, :refreshTokenTtl,
				     :version, :createdAt, :updatedAt)
				ON CONFLICT ON CONSTRAINT oauth_clients_client_identifier_key DO NOTHING
				""")
			.param("clientId", client.id().value())
			.param("tenantId", client.tenantId().value())
			.param("identifier", client.identifier().value())
			.param("displayName", client.displayName())
			.param("clientType", databaseValue(client.type()))
			.param("authenticationMethod", databaseValue(client.authenticationMethod()))
			.param("status", databaseValue(client.status()))
			.param("encodedSecret", stored.encodedSecret())
			.param("secretIssuedAt", databaseValue(client.secretMetadata(), ClientSecretMetadata::issuedAt))
			.param("secretExpiresAt", databaseValue(client.secretMetadata(), ClientSecretMetadata::expiresAt))
			.param("authorizationCodeTtl", Math.toIntExact(client.tokenPolicy().authorizationCodeTtl().toSeconds()))
			.param("accessTokenTtl", Math.toIntExact(client.tokenPolicy().accessTokenTtl().toSeconds()))
			.param("refreshTokensEnabled", client.tokenPolicy().refreshTokensEnabled())
			.param("refreshTokenTtl", Math.toIntExact(client.tokenPolicy().refreshTokenTtl().toSeconds()))
			.param("version", client.version())
			.param("createdAt", databaseValue(client.createdAt()))
			.param("updatedAt", databaseValue(client.updatedAt()))
			.update();
		if (affected == 0) {
			throw new ClientAlreadyExistsException(client.identifier());
		}
		if (affected != 1) {
			throw new IllegalStateException("Creating an OAuth client affected an unexpected number of rows: " + affected);
		}

		client.redirectUris()
			.stream()
			.sorted(Comparator.comparing(ClientRedirectUri::value))
			.forEach(uri -> insertRedirectUri(client, uri));
		client.postLogoutRedirectUris()
			.stream()
			.sorted(Comparator.comparing(ClientRedirectUri::value))
			.forEach(uri -> insertPostLogoutRedirectUri(client, uri));
		client.scopes()
			.stream()
			.sorted(Comparator.comparing(ClientScope::value))
			.forEach(scope -> insertScope(client, scope));
		return stored;
	}

	Optional<StoredOAuthClient> findById(TenantId tenantId, ClientId clientId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(clientId, "Client ID must not be null");
		Optional<ClientRow> row = this.jdbcClient
			.sql("SELECT " + CLIENT_COLUMNS + " FROM oauth_clients WHERE tenant_id = :tenantId AND client_id = :clientId")
			.param("tenantId", tenantId.value())
			.param("clientId", clientId.value())
			.query(CLIENT_ROW_MAPPER)
			.optional();
		return assemble(row);
	}

	Optional<StoredOAuthClient> findByIdentifier(ClientIdentifier identifier) {
		Objects.requireNonNull(identifier, "Client identifier must not be null");
		Optional<ClientRow> row = this.jdbcClient
			.sql("SELECT " + CLIENT_COLUMNS + " FROM oauth_clients WHERE client_identifier = :identifier")
			.param("identifier", identifier.value())
			.query(CLIENT_ROW_MAPPER)
			.optional();
		return assemble(row);
	}

	Optional<StoredOAuthClient> findActiveById(ClientId clientId) {
		Objects.requireNonNull(clientId, "Client ID must not be null");
		Optional<ClientRow> row = this.jdbcClient.sql("SELECT " + CLIENT_COLUMNS + """
				 FROM oauth_clients
				 WHERE client_id = :clientId
				   AND status = 'active'
				   AND EXISTS (
				       SELECT 1
				       FROM tenants
				       WHERE tenants.tenant_id = oauth_clients.tenant_id
				         AND tenants.status = 'active'
				   )
				""")
			.param("clientId", clientId.value())
			.query(CLIENT_ROW_MAPPER)
			.optional();
		return assemble(row);
	}

	Optional<StoredOAuthClient> findActiveByIdentifier(ClientIdentifier identifier) {
		Objects.requireNonNull(identifier, "Client identifier must not be null");
		Optional<ClientRow> row = this.jdbcClient.sql("SELECT " + CLIENT_COLUMNS + """
				 FROM oauth_clients
				 WHERE client_identifier = :identifier
				   AND status = 'active'
				   AND EXISTS (
				       SELECT 1
				       FROM tenants
				       WHERE tenants.tenant_id = oauth_clients.tenant_id
				         AND tenants.status = 'active'
				   )
				""")
			.param("identifier", identifier.value())
			.query(CLIENT_ROW_MAPPER)
			.optional();
		return assemble(row);
	}

	@Transactional(propagation = Propagation.MANDATORY)
	Optional<StoredOAuthClient> findByIdForShare(TenantId tenantId, ClientId clientId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(clientId, "Client ID must not be null");
		requireWriteTransaction();
		Optional<ClientRow> row = this.jdbcClient.sql("SELECT " + CLIENT_COLUMNS
				+ " FROM oauth_clients WHERE tenant_id = :tenantId AND client_id = :clientId FOR SHARE")
			.param("tenantId", tenantId.value())
			.param("clientId", clientId.value())
			.query(CLIENT_ROW_MAPPER)
			.optional();
		return assemble(row);
	}

	@Transactional(propagation = Propagation.MANDATORY, noRollbackFor = ClientConcurrentUpdateException.class)
	OAuthClient updateStatus(OAuthClient current, OAuthClient changed) {
		Objects.requireNonNull(current, "Current OAuth client must not be null");
		Objects.requireNonNull(changed, "Changed OAuth client must not be null");
		requireWriteTransaction();
		if (!current.id().equals(changed.id()) || !current.tenantId().equals(changed.tenantId())
				|| !current.identifier().equals(changed.identifier()) || !current.displayName().equals(changed.displayName())
				|| current.type() != changed.type()
				|| current.authenticationMethod() != changed.authenticationMethod()
				|| !Objects.equals(current.secretMetadata(), changed.secretMetadata())
				|| !current.redirectUris().equals(changed.redirectUris())
				|| !current.postLogoutRedirectUris().equals(changed.postLogoutRedirectUris())
				|| !current.scopes().equals(changed.scopes()) || !current.tokenPolicy().equals(changed.tokenPolicy())
				|| !current.createdAt().equals(changed.createdAt()) || current.status() == changed.status()
				|| current.version() == Long.MAX_VALUE || changed.version() != current.version() + 1
				|| changed.updatedAt().isBefore(current.updatedAt())) {
			throw new IllegalArgumentException(
					"Client status update must preserve ownership and registration data, and advance one version to a different status");
		}

		int affected = this.jdbcClient.sql("""
				UPDATE oauth_clients
				SET status = :newStatus, version = :newVersion, updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND client_id = :clientId
				  AND version = :expectedVersion
				  AND status = :expectedStatus
				""")
			.param("newStatus", databaseValue(changed.status()))
			.param("newVersion", changed.version())
			.param("updatedAt", databaseValue(changed.updatedAt()))
			.param("tenantId", current.tenantId().value())
			.param("clientId", current.id().value())
			.param("expectedVersion", current.version())
			.param("expectedStatus", databaseValue(current.status()))
			.update();
		if (affected == 0) {
			throw new ClientConcurrentUpdateException(current.tenantId(), current.id(), current.version());
		}
		if (affected != 1) {
			throw new IllegalStateException("Updating an OAuth client affected an unexpected number of rows: " + affected);
		}
		return changed;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	boolean upgradeEncodedSecret(ClientId clientId, String expectedEncoding, String replacementEncoding) {
		Objects.requireNonNull(clientId, "Client ID must not be null");
		validateEncodedSecret(expectedEncoding, "Expected client secret encoding");
		validateEncodedSecret(replacementEncoding, "Replacement client secret encoding");
		requireWriteTransaction();
		if (expectedEncoding.equals(replacementEncoding)) {
			return true;
		}

		int affected = this.jdbcClient.sql("""
				UPDATE oauth_clients
				SET encoded_client_secret = :replacementEncoding
				WHERE client_id = :clientId
				  AND encoded_client_secret = :expectedEncoding
				""")
			.param("replacementEncoding", replacementEncoding)
			.param("clientId", clientId.value())
			.param("expectedEncoding", expectedEncoding)
			.update();
		if (affected > 1) {
			throw new IllegalStateException(
					"Upgrading an OAuth client secret affected an unexpected number of rows: " + affected);
		}
		return affected == 1;
	}

	private void insertRedirectUri(OAuthClient client, ClientRedirectUri uri) {
		int affected = this.jdbcClient.sql("""
				INSERT INTO oauth_client_redirect_uris (tenant_id, client_id, redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", client.tenantId().value())
			.param("clientId", client.id().value())
			.param("redirectUri", uri.value())
			.update();
		requireSingleInsert("client redirect URI", affected);
	}

	private void insertPostLogoutRedirectUri(OAuthClient client, ClientRedirectUri uri) {
		int affected = this.jdbcClient.sql("""
				INSERT INTO oauth_client_post_logout_redirect_uris
				    (tenant_id, client_id, post_logout_redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", client.tenantId().value())
			.param("clientId", client.id().value())
			.param("redirectUri", uri.value())
			.update();
		requireSingleInsert("client post-logout redirect URI", affected);
	}

	private void insertScope(OAuthClient client, ClientScope scope) {
		int affected = this.jdbcClient.sql("""
				INSERT INTO oauth_client_scopes (tenant_id, client_id, scope)
				VALUES (:tenantId, :clientId, :scope)
				""")
			.param("tenantId", client.tenantId().value())
			.param("clientId", client.id().value())
			.param("scope", scope.value())
			.update();
		requireSingleInsert("client scope", affected);
	}

	private Optional<StoredOAuthClient> assemble(Optional<ClientRow> candidate) {
		if (candidate.isEmpty()) {
			return Optional.empty();
		}
		ClientRow row = candidate.orElseThrow();
		Set<ClientRedirectUri> redirectUris = redirectUris(row.tenantId(), row.clientId(),
				"oauth_client_redirect_uris", "redirect_uri");
		Set<ClientRedirectUri> postLogoutRedirectUris = redirectUris(row.tenantId(), row.clientId(),
				"oauth_client_post_logout_redirect_uris", "post_logout_redirect_uri");
		Set<ClientScope> scopes = scopes(row.tenantId(), row.clientId());
		return Optional.of(row.toStoredClient(redirectUris, postLogoutRedirectUris, scopes));
	}

	private Set<ClientRedirectUri> redirectUris(TenantId tenantId, ClientId clientId, String table, String column) {
		List<String> values = this.jdbcClient
			.sql("SELECT " + column + " FROM " + table
					+ " WHERE tenant_id = :tenantId AND client_id = :clientId ORDER BY " + column)
			.param("tenantId", tenantId.value())
			.param("clientId", clientId.value())
			.query(String.class)
			.list();
		Set<ClientRedirectUri> uris = new LinkedHashSet<>();
		values.stream().map(ClientRedirectUri::new).forEach(uris::add);
		return Set.copyOf(uris);
	}

	private Set<ClientScope> scopes(TenantId tenantId, ClientId clientId) {
		List<String> values = this.jdbcClient.sql("""
				SELECT scope
				FROM oauth_client_scopes
				WHERE tenant_id = :tenantId AND client_id = :clientId
				ORDER BY scope
				""")
			.param("tenantId", tenantId.value())
			.param("clientId", clientId.value())
			.query(String.class)
			.list();
		Set<ClientScope> scopes = new LinkedHashSet<>();
		values.stream().map(ClientScope::new).forEach(scopes::add);
		return Set.copyOf(scopes);
	}

	private static ClientRow mapClientRow(ResultSet resultSet, int rowNumber) throws SQLException {
		OffsetDateTime secretIssuedAt = resultSet.getObject("client_secret_issued_at", OffsetDateTime.class);
		OffsetDateTime secretExpiresAt = resultSet.getObject("client_secret_expires_at", OffsetDateTime.class);
		ClientSecretMetadata metadata = secretIssuedAt == null || secretExpiresAt == null ? null
				: new ClientSecretMetadata(secretIssuedAt.toInstant(), secretExpiresAt.toInstant());
		return new ClientRow(new ClientId(resultSet.getObject("client_id", UUID.class)),
				new TenantId(resultSet.getObject("tenant_id", UUID.class)),
				new ClientIdentifier(resultSet.getString("client_identifier")), resultSet.getString("display_name"),
				clientType(resultSet.getString("client_type")),
				authenticationMethod(resultSet.getString("authentication_method")),
				clientStatus(resultSet.getString("status")), metadata, resultSet.getString("encoded_client_secret"),
				new ClientTokenPolicy(Duration.ofSeconds(resultSet.getInt("authorization_code_ttl_seconds")),
						Duration.ofSeconds(resultSet.getInt("access_token_ttl_seconds")),
						resultSet.getBoolean("refresh_tokens_enabled"),
						Duration.ofSeconds(resultSet.getInt("refresh_token_ttl_seconds"))),
				resultSet.getLong("version"), resultSet.getObject("created_at", OffsetDateTime.class).toInstant(),
				resultSet.getObject("updated_at", OffsetDateTime.class).toInstant());
	}

	private static void requireSingleInsert(String resource, int affected) {
		if (affected != 1) {
			throw new IllegalStateException("Creating a " + resource + " affected an unexpected number of rows: " + affected);
		}
	}

	private static void validateEncodedSecret(String encodedSecret, String name) {
		Objects.requireNonNull(encodedSecret, name + " must not be null");
		if (encodedSecret.length() < 32 || encodedSecret.length() > 1024
				|| encodedSecret.regionMatches(true, 0, "{noop}", 0, 6)) {
			throw new IllegalArgumentException(name + " must be a supported one-way encoding");
		}
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("OAuth client write requires an existing read-write transaction");
		}
	}

	private static String databaseValue(ClientType type) {
		return switch (type) {
			case PUBLIC -> "public";
			case CONFIDENTIAL -> "confidential";
		};
	}

	private static String databaseValue(ClientAuthenticationMethod method) {
		return switch (method) {
			case NONE -> "none";
			case CLIENT_SECRET_BASIC -> "client_secret_basic";
		};
	}

	private static String databaseValue(ClientStatus status) {
		return switch (status) {
			case ACTIVE -> "active";
			case DISABLED -> "disabled";
		};
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private static OffsetDateTime databaseValue(ClientSecretMetadata metadata,
			java.util.function.Function<ClientSecretMetadata, Instant> value) {
		return metadata == null ? null : databaseValue(value.apply(metadata));
	}

	private static ClientType clientType(String value) {
		return switch (value) {
			case "public" -> ClientType.PUBLIC;
			case "confidential" -> ClientType.CONFIDENTIAL;
			default -> throw new IllegalStateException("Unsupported OAuth client type in the database: " + value);
		};
	}

	private static ClientAuthenticationMethod authenticationMethod(String value) {
		return switch (value) {
			case "none" -> ClientAuthenticationMethod.NONE;
			case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
			default -> throw new IllegalStateException(
					"Unsupported OAuth client authentication method in the database: " + value);
		};
	}

	private static ClientStatus clientStatus(String value) {
		return switch (value) {
			case "active" -> ClientStatus.ACTIVE;
			case "disabled" -> ClientStatus.DISABLED;
			default -> throw new IllegalStateException("Unsupported OAuth client status in the database: " + value);
		};
	}

	private record ClientRow(ClientId clientId, TenantId tenantId, ClientIdentifier identifier, String displayName,
			ClientType type, ClientAuthenticationMethod authenticationMethod, ClientStatus status,
			ClientSecretMetadata secretMetadata, String encodedSecret, ClientTokenPolicy tokenPolicy, long version,
			Instant createdAt, Instant updatedAt) {

		StoredOAuthClient toStoredClient(Set<ClientRedirectUri> redirectUris,
				Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes) {
			OAuthClient client = new OAuthClient(this.clientId, this.tenantId, this.identifier, this.displayName, this.type,
					this.authenticationMethod, this.status, this.secretMetadata, redirectUris, postLogoutRedirectUris,
					scopes, this.tokenPolicy, this.version, this.createdAt, this.updatedAt);
			return new StoredOAuthClient(client, this.encodedSecret);
		}

	}

}
