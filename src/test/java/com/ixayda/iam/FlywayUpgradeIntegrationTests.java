package com.ixayda.iam;

import java.util.UUID;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class FlywayUpgradeIntegrationTests extends ApplicationIntegrationTest {

	private static final int CURRENT_SCHEMA_VERSION = 25;

	private static final UUID TENANT_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742901");

	private static final UUID USER_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742902");

	private static final UUID CLIENT_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742903");

	private static final UUID GROUP_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742904");

	private static final UUID SESSION_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742905");

	private static final UUID AUTHORIZATION_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742906");

	private static final UUID TOKEN_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742907");

	private static final UUID INVALID_SERVICE_CLIENT_ID =
			UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742908");

	private static final UUID ADMIN_USER_ID =
			UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742909");

	private static final UUID ADMIN_APPROVER_ID =
			UUID.fromString("019c61d7-47d1-79ca-8052-1b731e74290a");

	@Autowired
	private DataSource dataSource;

	@Test
	void upgradesStoredDataFromTheHistoricalUserSchemaToTheCurrentSchema() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "3");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(3);
			insertHistoricalData(jdbc, schema);

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 3);

			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(count(jdbc, schema, "tenants")).isEqualTo(2);
			assertThat(count(jdbc, schema, "users")).isOne();
			assertThat(identifier(jdbc, schema)).isEqualTo("Alice@example.com|alice@example.com");
			assertThat(profileIsEmpty(jdbc, schema)).isTrue();
			assertThat(userVersions(jdbc, schema)).isEqualTo("7|7");
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesExistingClientsWithRefreshTokensDisabled() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "12");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(12);
			jdbc.sql("""
					INSERT INTO %s.oauth_clients
					    (client_id, tenant_id, client_identifier, display_name, client_type,
					     authentication_method)
					VALUES (:clientId, '00000000-0000-0000-0000-000000000001',
					        'upgrade-client', 'Upgrade Client', 'public', 'none')
					""".formatted(schema)).param("clientId", CLIENT_ID).update();

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 12);
			assertThat(jdbc.sql("""
					SELECT refresh_tokens_enabled::text || '|' || refresh_token_ttl_seconds
					FROM %s.oauth_clients
					WHERE client_id = :clientId
					""".formatted(schema)).param("clientId", CLIENT_ID).query(String.class).single())
				.isEqualTo("false|3600");
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesTheProfileSchemaToDirectoryGroups() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "14");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(14);

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 14);
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(count(jdbc, schema, "groups")).isZero();
			jdbc.sql("""
					INSERT INTO %s.groups (group_id, tenant_id, display_name)
					VALUES (:groupId, '00000000-0000-0000-0000-000000000001', 'Upgrade Group')
					""".formatted(schema))
				.param("groupId", UUID.randomUUID())
				.update();
			assertThat(count(jdbc, schema, "groups")).isOne();
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesDirectoryGroupsToDirectUserMemberships() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "15");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(15);
			jdbc.sql("""
					INSERT INTO %s.users (user_id, tenant_id)
					VALUES (:userId, '00000000-0000-0000-0000-000000000001')
					""".formatted(schema)).param("userId", USER_ID).update();
			jdbc.sql("""
					INSERT INTO %s.groups (group_id, tenant_id, display_name)
					VALUES (:groupId, '00000000-0000-0000-0000-000000000001', 'Upgrade Group')
					""".formatted(schema)).param("groupId", GROUP_ID).update();

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 15);
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(count(jdbc, schema, "users")).isOne();
			assertThat(count(jdbc, schema, "groups")).isOne();
			assertThat(count(jdbc, schema, "group_memberships")).isZero();
			jdbc.sql("""
					INSERT INTO %s.group_memberships (tenant_id, group_id, user_id)
					VALUES ('00000000-0000-0000-0000-000000000001', :groupId, :userId)
					""".formatted(schema))
				.param("groupId", GROUP_ID)
				.param("userId", USER_ID)
				.update();
			assertThat(count(jdbc, schema, "group_memberships")).isOne();
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesExistingAuthorizationsToExplicitAuthorizationCodeGrants() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "16");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(16);
			insertHistoricalAuthorization(jdbc, schema);

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 16);
			assertThat(jdbc.sql("""
					SELECT clients.authorization_grant_type || '|' || authorizations.authorization_grant_type
					       || '|' || tokens.authorization_grant_type
					FROM %s.oauth_clients clients
					JOIN %s.oauth_authorizations authorizations USING (tenant_id, client_id)
					JOIN %s.oauth_authorization_tokens tokens USING (tenant_id, client_id, authorization_id)
					WHERE clients.client_id = :clientId
					""".formatted(schema, schema, schema))
				.param("clientId", CLIENT_ID)
				.query(String.class)
				.single()).isEqualTo("authorization_code|authorization_code|authorization_code");
			assertThat(jdbc.sql("""
					SELECT factors.factor || '|' || (factors.issued_at = sessions.authenticated_at)
					FROM %s.user_session_authentication_factors factors
					JOIN %s.user_sessions sessions USING (tenant_id, session_id)
					WHERE factors.session_id = :sessionId
					""".formatted(schema, schema))
				.param("sessionId", SESSION_ID)
				.query(String.class)
				.single()).isEqualTo("password|true");
			assertThat(jdbc.sql("""
					SELECT redirect_uris.authorization_grant_type || '|'
					       || post_logout_uris.authorization_grant_type || '|'
					       || scopes.authorization_grant_type
					FROM %s.oauth_client_redirect_uris redirect_uris
					JOIN %s.oauth_client_post_logout_redirect_uris post_logout_uris
					  USING (tenant_id, client_id)
					JOIN %s.oauth_client_scopes scopes USING (tenant_id, client_id)
					WHERE redirect_uris.client_id = :clientId
					""".formatted(schema, schema, schema))
				.param("clientId", CLIENT_ID)
				.query(String.class)
				.single()).isEqualTo("authorization_code|authorization_code|authorization_code");
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesServiceScopesToGrantAwareTokenPolicy() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "17");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(17);
			insertHistoricalServiceClient(jdbc, schema);

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 17);
			assertThat(jdbc.sql("""
					SELECT status || '|' || authorization_grant_type || '|' || access_token_ttl_seconds
					FROM %s.oauth_clients
					WHERE client_id = :clientId
					""".formatted(schema))
				.param("clientId", CLIENT_ID)
				.query(String.class)
				.single()).isEqualTo("active|client_credentials|300");
			assertThat(jdbc.sql("""
					SELECT string_agg(authorization_grant_type || '|' || scope, ',' ORDER BY scope)
					FROM %s.oauth_client_scopes
					WHERE client_id = :clientId
					""".formatted(schema))
				.param("clientId", CLIENT_ID)
				.query(String.class)
				.single()).isEqualTo("client_credentials|scim.read");
			assertThat(jdbc.sql("""
					SELECT status || '|' ||
					       (SELECT count(*) FROM %s.oauth_client_scopes scopes
					        WHERE scopes.client_id = clients.client_id)
					FROM %s.oauth_clients clients
					WHERE client_id = :clientId
					""".formatted(schema, schema))
				.param("clientId", INVALID_SERVICE_CLIENT_ID)
				.query(String.class)
				.single()).isEqualTo("disabled|0");
			assertThat(jdbc.sql("""
					SELECT count(*)
					FROM %s.oauth_authorizations
					WHERE client_id = :clientId
					""".formatted(schema))
				.param("clientId", CLIENT_ID)
				.query(Integer.class)
				.single()).isZero();
			org.assertj.core.api.Assertions.assertThatThrownBy(() -> jdbc.sql("""
					UPDATE %s.oauth_clients
					SET access_token_ttl_seconds = 301
					WHERE client_id = :clientId
					""".formatted(schema)).param("clientId", CLIENT_ID).update())
				.isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
			org.assertj.core.api.Assertions.assertThatThrownBy(() -> jdbc.sql("""
					INSERT INTO %s.oauth_client_scopes
					    (tenant_id, client_id, authorization_grant_type, scope)
					VALUES
					    ('00000000-0000-0000-0000-000000000001', :clientId,
					     'client_credentials', 'openid')
					""".formatted(schema)).param("clientId", CLIENT_ID).update())
				.isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesExistingInstallationsToAdminRbac() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "20");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(20);

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 20);
			assertThat(count(jdbc, schema, "admin_roles")).isEqualTo(5);
			assertThat(count(jdbc, schema, "admin_permissions")).isEqualTo(23);
			assertThat(count(jdbc, schema, "admin_role_permissions")).isEqualTo(38);
			assertThat(count(jdbc, schema, "admin_role_grant_rules")).isEqualTo(8);
			assertThat(count(jdbc, schema, "admin_role_bindings")).isZero();
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void preservesExistingAdminRoleBindingsWhenAddingLifecycleHistory() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "21");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(21);
			jdbc.sql("""
					INSERT INTO %s.users (user_id, tenant_id)
					VALUES
					    (:adminUserId, '00000000-0000-0000-0000-000000000001'),
					    (:approverId, '00000000-0000-0000-0000-000000000001')
					""".formatted(schema))
				.param("adminUserId", ADMIN_USER_ID)
				.param("approverId", ADMIN_APPROVER_ID)
				.update();
			jdbc.sql("""
					INSERT INTO %s.admin_role_bindings
					    (tenant_id, user_id, role_code, binding_type, created_by_user_id,
					     reason, expires_at, created_at, updated_at)
					VALUES
					    ('00000000-0000-0000-0000-000000000001', :adminUserId,
					     'support', 'permanent', :approverId, 'Support rotation', NULL,
					     '2026-07-20T00:00:00Z', '2026-07-20T00:00:00Z'),
					    ('00000000-0000-0000-0000-000000000001', :adminUserId,
					     'auditor', 'jit', :approverId, 'Incident review',
					     '2026-07-20T04:00:00Z', '2026-07-20T00:00:00Z', '2026-07-20T00:00:00Z')
					""".formatted(schema))
				.param("adminUserId", ADMIN_USER_ID)
				.param("approverId", ADMIN_APPROVER_ID)
				.update();

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 21);
			assertThat(jdbc.sql("""
					SELECT count(*) = 2
					   AND count(DISTINCT binding_id) = 2
					   AND bool_and(status = 'active')
					   AND bool_and(version = 0)
					   AND bool_and(revoked_by_user_id IS NULL)
					   AND bool_and(revoked_at IS NULL)
					FROM %s.admin_role_bindings
					WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
					  AND user_id = :adminUserId
					""".formatted(schema))
				.param("adminUserId", ADMIN_USER_ID)
				.query(Boolean.class)
				.single()).isTrue();
			assertThat(jdbc.sql("""
					SELECT string_agg(role_code || ':' || binding_type || ':' || reason, ',' ORDER BY role_code)
					FROM %s.admin_role_bindings
					WHERE user_id = :adminUserId
					""".formatted(schema))
				.param("adminUserId", ADMIN_USER_ID)
				.query(String.class)
				.single()).isEqualTo("auditor:jit:Incident review,support:permanent:Support rotation");
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesAdminRbacInstallationsToEncryptedTotpCredentialStorage() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "22");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(22);
			jdbc.sql("""
					INSERT INTO %s.users (user_id, tenant_id)
					VALUES (:userId, '00000000-0000-0000-0000-000000000001')
					""".formatted(schema)).param("userId", USER_ID).update();

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(CURRENT_SCHEMA_VERSION - 22);
			assertThat(count(jdbc, schema, "user_totp_credentials")).isZero();
			jdbc.sql("""
					INSERT INTO %s.user_totp_credentials
					    (credential_id, tenant_id, user_id, status, secret_encryption_key_id,
					     secret_initialization_vector, secret_ciphertext, created_at, updated_at,
					     enrollment_expires_at)
					VALUES
					    (:credentialId, '00000000-0000-0000-0000-000000000001', :userId,
					     'pending', 'v1', decode(repeat('01', 12), 'hex'),
					     decode(repeat('02', 36), 'hex'), '2026-07-20T00:00:00Z',
					     '2026-07-20T00:00:00Z', '2026-07-20T00:10:00Z')
					""".formatted(schema))
				.param("credentialId", UUID.randomUUID())
				.param("userId", USER_ID)
				.update();

			assertThat(count(jdbc, schema, "user_totp_credentials")).isOne();
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(CURRENT_SCHEMA_VERSION);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	private Flyway flyway(String schema, String target) {
		var configuration = Flyway.configure()
			.dataSource(this.dataSource)
			.locations("classpath:db/migration")
			.defaultSchema(schema)
			.schemas(schema)
			.createSchemas(true)
			.cleanDisabled(true)
			.failOnMissingLocations(true)
			.outOfOrder(false)
			.validateMigrationNaming(true)
			.validateOnMigrate(true);
		if (target != null) {
			configuration.target(target);
		}
		return configuration.load();
	}

	private static void insertHistoricalData(JdbcClient jdbc, String schema) {
		jdbc.sql(("""
				INSERT INTO %s.tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'upgrade-test', 'Upgrade Test')
				""").formatted(schema)).param("tenantId", TENANT_ID).update();
		jdbc.sql(("""
				INSERT INTO %s.users (user_id, tenant_id, version)
				VALUES (:userId, :tenantId, 7)
				""").formatted(schema)).param("userId", USER_ID).param("tenantId", TENANT_ID).update();
		jdbc.sql(("""
				INSERT INTO %s.user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value)
				VALUES
				    (:tenantId, :userId, 'email', 'Alice@example.com', 'alice@example.com')
				""").formatted(schema)).param("tenantId", TENANT_ID).param("userId", USER_ID).update();
	}

	private static void insertHistoricalAuthorization(JdbcClient jdbc, String schema) {
		jdbc.sql("""
				INSERT INTO %s.users (user_id, tenant_id)
				VALUES (:userId, '00000000-0000-0000-0000-000000000001')
				""".formatted(schema)).param("userId", USER_ID).update();
		jdbc.sql("""
				INSERT INTO %s.user_sessions
				    (tenant_id, session_id, user_id, authentication_method, status,
				     issued_tenant_version, issued_user_version, authenticated_at, expires_at)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :sessionId, :userId, 'password', 'active',
				     0, 0, now(), now() + interval '1 hour')
				""".formatted(schema)).param("sessionId", SESSION_ID).param("userId", USER_ID).update();
		jdbc.sql("""
				INSERT INTO %s.oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type, authentication_method)
				VALUES
				    (:clientId, '00000000-0000-0000-0000-000000000001',
				     'historical-authorization-client', 'Historical Authorization Client', 'public', 'none')
				""".formatted(schema)).param("clientId", CLIENT_ID).update();
		jdbc.sql("""
				INSERT INTO %s.oauth_client_redirect_uris (tenant_id, client_id, redirect_uri)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :clientId,
				     'https://client.example.test/callback')
				""".formatted(schema)).param("clientId", CLIENT_ID).update();
		jdbc.sql("""
				INSERT INTO %s.oauth_client_post_logout_redirect_uris
				    (tenant_id, client_id, post_logout_redirect_uri)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :clientId,
				     'https://client.example.test/logout/callback')
				""".formatted(schema)).param("clientId", CLIENT_ID).update();
		jdbc.sql("""
				INSERT INTO %s.oauth_client_scopes (tenant_id, client_id, scope)
				VALUES ('00000000-0000-0000-0000-000000000001', :clientId, 'openid')
				""".formatted(schema)).param("clientId", CLIENT_ID).update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorizations
				    (authorization_id, tenant_id, client_id, user_id, session_id, client_identifier,
				     principal_name, authorization_uri, request_parameters, purge_at)
				VALUES
				    (:authorizationId, '00000000-0000-0000-0000-000000000001', :clientId, :userId,
				     :sessionId, 'historical-authorization-client', :principalName,
				     'https://issuer.example.test/oauth2/authorize',
				     '{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","code_challenge_method":"S256"}',
				     now() + interval '1 hour')
				""".formatted(schema))
			.param("authorizationId", AUTHORIZATION_ID)
			.param("clientId", CLIENT_ID)
			.param("userId", USER_ID)
			.param("sessionId", SESSION_ID)
			.param("principalName", USER_ID.toString())
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorization_tokens
				    (token_id, tenant_id, client_id, authorization_id, token_type, token_digest,
				     encryption_key_id, initialization_vector, ciphertext, issued_at, expires_at)
				VALUES
				    (:tokenId, '00000000-0000-0000-0000-000000000001', :clientId, :authorizationId,
				     'state', decode(repeat('01', 32), 'hex'), 'test-key', decode(repeat('02', 12), 'hex'),
				     decode(repeat('03', 17), 'hex'), now(), now() + interval '5 minutes')
				""".formatted(schema))
			.param("tokenId", TOKEN_ID)
			.param("clientId", CLIENT_ID)
			.param("authorizationId", AUTHORIZATION_ID)
			.update();
	}

	private static void insertHistoricalServiceClient(JdbcClient jdbc, String schema) {
		jdbc.sql("""
				INSERT INTO %s.oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type,
				     authentication_method, authorization_grant_type, encoded_client_secret,
				     client_secret_issued_at, client_secret_expires_at)
				VALUES
				    (:clientId, '00000000-0000-0000-0000-000000000001', 'historical-service-client',
				     'Historical Service Client', 'confidential', 'client_secret_basic', 'client_credentials',
				     '{test}abcdefghijklmnopqrstuvwxyz0123456789', now(), now() + interval '1 day'),
				    (:invalidClientId, '00000000-0000-0000-0000-000000000001',
				     'historical-invalid-service-client', 'Historical Invalid Service Client',
				     'confidential', 'client_secret_basic', 'client_credentials',
				     '{test}abcdefghijklmnopqrstuvwxyz0123456789', now(), now() + interval '1 day')
				""".formatted(schema))
			.param("clientId", CLIENT_ID)
			.param("invalidClientId", INVALID_SERVICE_CLIENT_ID)
			.update();
		jdbc.sql("""
				UPDATE %s.oauth_clients
				SET access_token_ttl_seconds = 600
				WHERE client_id IN (:clientId, :invalidClientId)
				""".formatted(schema))
			.param("clientId", CLIENT_ID)
			.param("invalidClientId", INVALID_SERVICE_CLIENT_ID)
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_client_scopes (tenant_id, client_id, scope)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :clientId, 'scim.read'),
				    ('00000000-0000-0000-0000-000000000001', :clientId, 'openid'),
				    ('00000000-0000-0000-0000-000000000001', :clientId, 'profile'),
				    ('00000000-0000-0000-0000-000000000001', :invalidClientId, 'openid')
				""".formatted(schema))
			.param("clientId", CLIENT_ID)
			.param("invalidClientId", INVALID_SERVICE_CLIENT_ID)
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorizations
				    (authorization_id, tenant_id, client_id, client_identifier, principal_name,
				     authorization_grant_type, request_parameters, created_at, updated_at, purge_at)
				VALUES
				    (:authorizationId, '00000000-0000-0000-0000-000000000001', :clientId,
				     'historical-service-client', 'historical-service-client', 'client_credentials',
				     '{}'::jsonb, now(), now(), now() + interval '1 hour')
				""".formatted(schema))
			.param("authorizationId", AUTHORIZATION_ID)
			.param("clientId", CLIENT_ID)
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorization_requested_scopes
				    (tenant_id, client_id, authorization_id, scope)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :clientId, :authorizationId, 'openid')
				""".formatted(schema))
			.param("clientId", CLIENT_ID)
			.param("authorizationId", AUTHORIZATION_ID)
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorization_scopes
				    (tenant_id, client_id, authorization_id, scope)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :clientId, :authorizationId, 'openid')
				""".formatted(schema))
			.param("clientId", CLIENT_ID)
			.param("authorizationId", AUTHORIZATION_ID)
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorization_tokens
				    (token_id, tenant_id, client_id, authorization_id, authorization_grant_type,
				     token_type, token_digest, encryption_key_id, initialization_vector, ciphertext,
				     access_token_type, claims_version, claims, issued_at, expires_at)
				VALUES
				    (:tokenId, '00000000-0000-0000-0000-000000000001', :clientId, :authorizationId,
				     'client_credentials', 'access_token', decode(repeat('11', 32), 'hex'), 'test-key',
				     decode(repeat('12', 12), 'hex'), decode(repeat('13', 17), 'hex'),
				     'Bearer', 1, '{}'::jsonb, now(), now() + interval '5 minutes')
				""".formatted(schema))
			.param("tokenId", TOKEN_ID)
			.param("clientId", CLIENT_ID)
			.param("authorizationId", AUTHORIZATION_ID)
			.update();
		jdbc.sql("""
				INSERT INTO %s.oauth_authorization_token_scopes
				    (tenant_id, client_id, authorization_id, token_id, scope)
				VALUES
				    ('00000000-0000-0000-0000-000000000001', :clientId, :authorizationId, :tokenId, 'openid')
				""".formatted(schema))
			.param("clientId", CLIENT_ID)
			.param("authorizationId", AUTHORIZATION_ID)
			.param("tokenId", TOKEN_ID)
			.update();
	}

	private static int count(JdbcClient jdbc, String schema, String table) {
		return jdbc.sql("SELECT count(*) FROM " + schema + "." + table).query(Integer.class).single();
	}

	private static int migrationCount(JdbcClient jdbc, String schema) {
		String query = "SELECT count(*) FROM " + schema
				+ ".flyway_schema_history WHERE version IS NOT NULL AND success";
		return jdbc.sql(query)
			.query(Integer.class)
			.single();
	}

	private static String identifier(JdbcClient jdbc, String schema) {
		return jdbc.sql("""
				SELECT identifier_value || '|' || canonical_value
				FROM %s.user_login_identifiers
				WHERE tenant_id = :tenantId AND user_id = :userId
				""".formatted(schema))
			.param("tenantId", TENANT_ID)
			.param("userId", USER_ID)
			.query(String.class)
			.single();
	}

	private static boolean profileIsEmpty(JdbcClient jdbc, String schema) {
		return jdbc.sql("""
				SELECT display_name IS NULL AND formatted_name IS NULL
				       AND given_name IS NULL AND family_name IS NULL
				FROM %s.users
				WHERE tenant_id = :tenantId AND user_id = :userId
				""".formatted(schema))
			.param("tenantId", TENANT_ID)
			.param("userId", USER_ID)
			.query(Boolean.class)
			.single();
	}

	private static String userVersions(JdbcClient jdbc, String schema) {
		return jdbc.sql("""
				SELECT version::text || '|' || security_version
				FROM %s.users
				WHERE tenant_id = :tenantId AND user_id = :userId
				""".formatted(schema))
			.param("tenantId", TENANT_ID)
			.param("userId", USER_ID)
			.query(String.class)
			.single();
	}

}
