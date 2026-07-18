package com.ixayda.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class OAuthAuthorizationSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43001");

	private static final UUID FIRST_USER_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43002");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43003");

	private static final UUID FIRST_SESSION_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43004");

	private static final UUID SECOND_SESSION_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43005");

	private static final UUID FIRST_CLIENT_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43006");

	private static final UUID SECOND_CLIENT_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43007");

	private static final UUID FIRST_AUTHORIZATION_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43008");

	private static final UUID SECOND_AUTHORIZATION_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e43009");

	private static final UUID FIRST_TOKEN_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e4300a");

	private static final UUID SECOND_TOKEN_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e4300b");

	private static final UUID THIRD_TOKEN_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e4300c");

	private static final UUID FOURTH_TOKEN_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e4300d");

	private static final UUID FIFTH_TOKEN_ID =
			UUID.fromString("019cbb8a-50a8-7a40-b1f9-cde6d1e4300e");

	private static final OffsetDateTime ISSUED_AT =
			OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);

	private static final String REDIRECT_URI = "https://client.example.test/callback";

	private static final String REQUEST_PARAMETERS = """
			{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
			"code_challenge_method":"S256","nonce":"oidc-nonce"}
			""";

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createFixtures() {
		insertTenant();
		insertUser(TenantId.DEFAULT.value(), FIRST_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);
		insertSession(TenantId.DEFAULT.value(), FIRST_USER_ID, FIRST_SESSION_ID);
		insertSession(SECOND_TENANT_ID, SECOND_USER_ID, SECOND_SESSION_ID);
		insertClient(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "authorization-schema-first");
		insertClient(SECOND_TENANT_ID, SECOND_CLIENT_ID, "authorization-schema-second");
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM oauth_authorizations
				WHERE authorization_id IN (:firstAuthorizationId, :secondAuthorizationId)
				""")
			.param("firstAuthorizationId", FIRST_AUTHORIZATION_ID)
			.param("secondAuthorizationId", SECOND_AUTHORIZATION_ID)
			.update();
		this.jdbcClient.sql("""
				DELETE FROM oauth_authorization_consents
				WHERE client_id IN (:firstClientId, :secondClientId)
				""")
			.param("firstClientId", FIRST_CLIENT_ID)
			.param("secondClientId", SECOND_CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM oauth_clients WHERE client_id IN (:firstClientId, :secondClientId)")
			.param("firstClientId", FIRST_CLIENT_ID)
			.param("secondClientId", SECOND_CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE session_id IN (:firstSessionId, :secondSessionId)")
			.param("firstSessionId", FIRST_SESSION_ID)
			.param("secondSessionId", SECOND_SESSION_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstUserId, :secondUserId)")
			.param("firstUserId", FIRST_USER_ID)
			.param("secondUserId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesNormalizedTenantOwnedAuthorizationAndConsentState() {
		insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID, FIRST_SESSION_ID,
				FIRST_AUTHORIZATION_ID, "authorization-schema-first", FIRST_USER_ID.toString(), REQUEST_PARAMETERS);
		insertRequestedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "openid");
		insertRequestedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "api.read");
		insertAuthorizedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "openid");
		insertPrincipalAuthority(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "ROLE_USER");
		insertToken(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, FIRST_TOKEN_ID, "state",
				bytes(32, (byte) 1), bytes(12, (byte) 2), bytes(17, (byte) 3), null, null);
		insertConsent(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID, FIRST_USER_ID.toString());
		insertConsentAuthority(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID, "SCOPE_openid");

		assertThat(count("oauth_authorizations")).isOne();
		assertThat(count("oauth_authorization_requested_scopes")).isEqualTo(2);
		assertThat(count("oauth_authorization_scopes")).isOne();
		assertThat(count("oauth_authorization_principal_authorities")).isOne();
		assertThat(count("oauth_authorization_tokens")).isOne();
		assertThat(count("oauth_authorization_consents")).isOne();
		assertThat(count("oauth_authorization_consent_authorities")).isOne();
		assertThat(this.jdbcClient.sql("""
				SELECT octet_length(token_digest) = 32
				   AND octet_length(initialization_vector) = 12
				   AND octet_length(ciphertext) = 17
				FROM oauth_authorization_tokens
				WHERE token_id = :tokenId
				""")
			.param("tokenId", FIRST_TOKEN_ID)
			.query(Boolean.class)
			.single()).isTrue();

		this.jdbcClient.sql("DELETE FROM oauth_authorizations WHERE authorization_id = :authorizationId")
			.param("authorizationId", FIRST_AUTHORIZATION_ID)
			.update();

		assertThat(count("oauth_authorization_requested_scopes")).isZero();
		assertThat(count("oauth_authorization_scopes")).isZero();
		assertThat(count("oauth_authorization_principal_authorities")).isZero();
		assertThat(count("oauth_authorization_tokens")).isZero();
		assertThat(count("oauth_authorization_consents")).isOne();
	}

	@Test
	void storesClientCredentialsAuthorizationWithoutUserOrRequestState() {
		configureClientCredentialsGrant(FIRST_CLIENT_ID);
		insertClientCredentialsAuthorization(FIRST_AUTHORIZATION_ID);
		insertRequestedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "api.read");
		insertAuthorizedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "api.read");
		insertToken(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, FIRST_TOKEN_ID,
				"client_credentials", "access_token", bytes(32, (byte) 31), bytes(12, (byte) 32),
				bytes(17, (byte) 33), "Bearer", "{\"sub\":\"authorization-schema-first\"}", "test-v1");
		insertTokenScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, FIRST_TOKEN_ID,
				"api.read");

		assertThat(this.jdbcClient.sql("""
				SELECT user_id IS NULL AND session_id IS NULL AND authorization_uri IS NULL
				       AND redirect_uri IS NULL AND client_state IS NULL
				       AND request_parameters = '{}'::jsonb
				       AND authorization_grant_type = 'client_credentials'
				FROM oauth_authorizations
				WHERE authorization_id = :authorizationId
				""")
			.param("authorizationId", FIRST_AUTHORIZATION_ID)
			.query(Boolean.class)
			.single()).isTrue();
		assertThat(this.jdbcClient.sql("""
				SELECT authorization_grant_type
				FROM oauth_authorization_tokens
				WHERE token_id = :tokenId
				""")
			.param("tokenId", FIRST_TOKEN_ID)
			.query(String.class)
			.single()).isEqualTo("client_credentials");

		this.jdbcClient.sql("DELETE FROM oauth_authorizations WHERE authorization_id = :authorizationId")
			.param("authorizationId", FIRST_AUTHORIZATION_ID)
			.update();
		assertThat(count("oauth_authorization_tokens")).isZero();
		assertThat(count("oauth_authorization_token_scopes")).isZero();
	}

	@Test
	void rejectsCrossTenantAndUnregisteredAuthorizationState() {
		assertThatThrownBy(() -> insertAuthorization(SECOND_TENANT_ID, FIRST_CLIENT_ID, SECOND_USER_ID,
				SECOND_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-first", SECOND_USER_ID.toString(),
				REQUEST_PARAMETERS)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, SECOND_USER_ID,
				SECOND_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-first", SECOND_USER_ID.toString(),
				REQUEST_PARAMETERS)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID,
				FIRST_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-first", "mutable-user-name",
				REQUEST_PARAMETERS)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID,
				FIRST_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-second", FIRST_USER_ID.toString(),
				REQUEST_PARAMETERS)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID,
				FIRST_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-first", FIRST_USER_ID.toString(),
				"""
				{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\
				"code_challenge_method":"plain","unknown":"value"}
				""")).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID,
				FIRST_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-first", FIRST_USER_ID.toString(),
				"""
				{"code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
				""")).isInstanceOf(DataIntegrityViolationException.class);

		insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID, FIRST_SESSION_ID,
				FIRST_AUTHORIZATION_ID, "authorization-schema-first", FIRST_USER_ID.toString(), REQUEST_PARAMETERS);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_authorizations
				SET purge_at = updated_at
				WHERE authorization_id = :authorizationId
				""").param("authorizationId", FIRST_AUTHORIZATION_ID).update())
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRequestedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID,
				FIRST_AUTHORIZATION_ID, "unregistered"))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void rejectsMixedAuthorizationGrantShapes() {
		this.jdbcClient.sql("DELETE FROM oauth_client_redirect_uris WHERE client_id = :clientId")
			.param("clientId", FIRST_CLIENT_ID)
			.update();
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_clients
				SET authorization_grant_type = 'client_credentials'
				WHERE client_id = :clientId
				""").param("clientId", FIRST_CLIENT_ID).update())
			.isInstanceOf(DataIntegrityViolationException.class);

		insertAuthorization(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_USER_ID, SECOND_SESSION_ID,
				SECOND_AUTHORIZATION_ID, "authorization-schema-second", SECOND_USER_ID.toString(), REQUEST_PARAMETERS);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_authorizations
				SET authorization_uri = NULL
				WHERE authorization_id = :authorizationId
				""").param("authorizationId", SECOND_AUTHORIZATION_ID).update())
			.isInstanceOf(DataIntegrityViolationException.class);

		configureClientCredentialsGrant(FIRST_CLIENT_ID);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO oauth_client_redirect_uris (tenant_id, client_id, redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("clientId", FIRST_CLIENT_ID)
			.param("redirectUri", REDIRECT_URI)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO oauth_client_post_logout_redirect_uris
				    (tenant_id, client_id, post_logout_redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("clientId", FIRST_CLIENT_ID)
			.param("redirectUri", "https://client.example.test/logout/callback")
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID,
				FIRST_SESSION_ID, FIRST_AUTHORIZATION_ID, "authorization-schema-first", FIRST_USER_ID.toString(),
				REQUEST_PARAMETERS)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO oauth_authorizations
				    (authorization_id, tenant_id, client_id, user_id, session_id, client_identifier,
				     principal_name, authorization_grant_type, request_parameters, purge_at)
				VALUES
				    (:authorizationId, :tenantId, :clientId, :userId, :sessionId, 'authorization-schema-first',
				     'authorization-schema-first', 'client_credentials', '{}'::jsonb, now() + interval '1 hour')
				""")
			.param("authorizationId", FIRST_AUTHORIZATION_ID)
			.param("tenantId", TenantId.DEFAULT.value())
			.param("clientId", FIRST_CLIENT_ID)
			.param("userId", FIRST_USER_ID)
			.param("sessionId", FIRST_SESSION_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);

		insertClientCredentialsAuthorization(FIRST_AUTHORIZATION_ID);
		assertThatThrownBy(() -> insertToken(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID,
				FIRST_TOKEN_ID, "client_credentials", "refresh_token", bytes(32, (byte) 34), bytes(12, (byte) 35),
				bytes(17, (byte) 36), null, null, "test-v1"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID,
				FIRST_TOKEN_ID, "authorization_code", "access_token", bytes(32, (byte) 37), bytes(12, (byte) 38),
				bytes(17, (byte) 39), "Bearer", "{}", "test-v1"))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void enforcesProtectedUniqueTokenLookupsAndAccessTokenScopes() {
		insertAuthorization(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_USER_ID, FIRST_SESSION_ID,
				FIRST_AUTHORIZATION_ID, "authorization-schema-first", FIRST_USER_ID.toString(), REQUEST_PARAMETERS);
		insertAuthorization(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_USER_ID, SECOND_SESSION_ID,
				SECOND_AUTHORIZATION_ID, "authorization-schema-second", SECOND_USER_ID.toString(), REQUEST_PARAMETERS);
		insertRequestedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "openid");
		insertAuthorizedScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, "openid");
		byte[] digest = bytes(32, (byte) 7);
		insertToken(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, FIRST_TOKEN_ID,
				"access_token", digest, bytes(12, (byte) 8), bytes(17, (byte) 9), "Bearer", "{}");
		insertTokenScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID, FIRST_TOKEN_ID, "openid");
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_authorization_tokens
				SET claims_version = NULL
				WHERE token_id = :tokenId
				""").param("tokenId", FIRST_TOKEN_ID).update())
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_authorization_tokens
				SET invalidated_at = updated_at + interval '1 second'
				WHERE token_id = :tokenId
				""").param("tokenId", FIRST_TOKEN_ID).update())
			.isInstanceOf(DataIntegrityViolationException.class);

		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "state", digest, bytes(12, (byte) 10), bytes(17, (byte) 11), null, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "state", bytes(31, (byte) 1), bytes(12, (byte) 2), bytes(17, (byte) 3), null,
				null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "state", bytes(32, (byte) 1), bytes(11, (byte) 2), bytes(17, (byte) 3), null,
				null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "authorization_code", bytes(32, (byte) 4), bytes(12, (byte) 5),
				bytes(17, (byte) 6), "Bearer", null)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "access_token", bytes(32, (byte) 12), bytes(12, (byte) 13),
				bytes(17, (byte) 14), null, "{}"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "id_token", bytes(32, (byte) 15), bytes(12, (byte) 16),
				bytes(17, (byte) 17), null, "null"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, FIRST_AUTHORIZATION_ID,
				FOURTH_TOKEN_ID, "refresh_token", bytes(32, (byte) 22), bytes(12, (byte) 23),
				bytes(17, (byte) 24), null, "{}"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				SECOND_TOKEN_ID, "state", bytes(32, (byte) 18), bytes(12, (byte) 8),
				bytes(17, (byte) 19), null, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID, THIRD_TOKEN_ID, "state",
				bytes(32, (byte) 20), bytes(12, (byte) 8), bytes(17, (byte) 21), null, null, "test-v2");
		insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID, FIFTH_TOKEN_ID, "refresh_token",
				bytes(32, (byte) 25), bytes(12, (byte) 26), bytes(17, (byte) 27), null, null);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				UPDATE oauth_authorization_tokens
				SET access_token_type = 'Bearer'
				WHERE token_id = :tokenId
				""").param("tokenId", FIFTH_TOKEN_ID).update())
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertTokenScope(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				FIFTH_TOKEN_ID, "openid"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertToken(SECOND_TENANT_ID, SECOND_CLIENT_ID, SECOND_AUTHORIZATION_ID,
				FOURTH_TOKEN_ID, "refresh_token", bytes(32, (byte) 28), bytes(12, (byte) 29),
				bytes(17, (byte) 30), null, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(count("oauth_authorization_tokens")).isEqualTo(3);

		this.jdbcClient.sql("""
				DELETE FROM oauth_authorization_scopes
				WHERE authorization_id = :authorizationId AND scope = 'openid'
				""").param("authorizationId", FIRST_AUTHORIZATION_ID).update();
		assertThat(count("oauth_authorization_token_scopes")).isOne();
	}

	private void insertTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'authorization-schema', 'Authorization Schema')
				""").param("tenantId", SECOND_TENANT_ID).update();
	}

	private void insertUser(UUID tenantId, UUID userId) {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.update();
	}

	private void insertSession(UUID tenantId, UUID userId, UUID sessionId) {
		this.jdbcClient.sql("""
				INSERT INTO user_sessions
				    (tenant_id, session_id, user_id, authentication_method, issued_tenant_version,
				     issued_user_version, authenticated_at, updated_at, expires_at)
				VALUES
				    (:tenantId, :sessionId, :userId, 'password', 0, 0,
				     :issuedAt, :issuedAt, :expiresAt)
				""")
			.param("tenantId", tenantId)
			.param("sessionId", sessionId)
			.param("userId", userId)
			.param("issuedAt", ISSUED_AT)
			.param("expiresAt", ISSUED_AT.plusHours(8))
			.update();
	}

	private void insertClient(UUID tenantId, UUID clientId, String identifier) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type,
				     authentication_method)
				VALUES (:clientId, :tenantId, :identifier, 'Authorization Schema Client', 'public', 'none')
				""")
			.param("clientId", clientId)
			.param("tenantId", tenantId)
			.param("identifier", identifier)
			.update();
		this.jdbcClient.sql("""
				INSERT INTO oauth_client_redirect_uris (tenant_id, client_id, redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("redirectUri", REDIRECT_URI)
			.update();
		for (String scope : new String[] { "openid", "api.read" }) {
			this.jdbcClient.sql("""
					INSERT INTO oauth_client_scopes (tenant_id, client_id, scope)
					VALUES (:tenantId, :clientId, :scope)
					""")
				.param("tenantId", tenantId)
				.param("clientId", clientId)
				.param("scope", scope)
				.update();
		}
	}

	private void configureClientCredentialsGrant(UUID clientId) {
		this.jdbcClient.sql("DELETE FROM oauth_client_redirect_uris WHERE client_id = :clientId")
			.param("clientId", clientId)
			.update();
		this.jdbcClient.sql("""
				UPDATE oauth_clients
				SET client_type = 'confidential',
				    authentication_method = 'client_secret_basic',
				    encoded_client_secret = '{test}abcdefghijklmnopqrstuvwxyz0123456789',
				    client_secret_issued_at = created_at,
				    client_secret_expires_at = created_at + interval '1 day',
				    authorization_grant_type = 'client_credentials'
				WHERE client_id = :clientId
				""")
			.param("clientId", clientId)
			.update();
	}

	private void insertAuthorization(UUID tenantId, UUID clientId, UUID userId, UUID sessionId,
			UUID authorizationId, String identifier, String principalName, String requestParameters) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorizations
				    (authorization_id, tenant_id, client_id, user_id, session_id, client_identifier,
				     principal_name, authorization_uri, redirect_uri, client_state,
				     request_parameters, created_at, updated_at, purge_at)
				VALUES
				    (:authorizationId, :tenantId, :clientId, :userId, :sessionId, :identifier,
				     :principalName, 'https://issuer.example.test/oauth2/authorize', :redirectUri,
				     'client-state', CAST(:requestParameters AS jsonb), :issuedAt, :issuedAt, :purgeAt)
				""")
			.param("authorizationId", authorizationId)
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("userId", userId)
			.param("sessionId", sessionId)
			.param("identifier", identifier)
			.param("principalName", principalName)
			.param("redirectUri", REDIRECT_URI)
			.param("requestParameters", requestParameters)
			.param("issuedAt", ISSUED_AT)
			.param("purgeAt", ISSUED_AT.plusDays(1))
			.update();
	}

	private void insertClientCredentialsAuthorization(UUID authorizationId) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorizations
				    (authorization_id, tenant_id, client_id, client_identifier, principal_name,
				     authorization_grant_type, request_parameters, created_at, updated_at, purge_at)
				VALUES
				    (:authorizationId, :tenantId, :clientId, 'authorization-schema-first',
				     'authorization-schema-first', 'client_credentials', '{}'::jsonb,
				     :issuedAt, :issuedAt, :purgeAt)
				""")
			.param("authorizationId", authorizationId)
			.param("tenantId", TenantId.DEFAULT.value())
			.param("clientId", FIRST_CLIENT_ID)
			.param("issuedAt", ISSUED_AT)
			.param("purgeAt", ISSUED_AT.plusDays(1))
			.update();
	}

	private void insertRequestedScope(UUID tenantId, UUID clientId, UUID authorizationId, String scope) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_requested_scopes
				    (tenant_id, client_id, authorization_id, scope)
				VALUES (:tenantId, :clientId, :authorizationId, :scope)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("authorizationId", authorizationId)
			.param("scope", scope)
			.update();
	}

	private void insertAuthorizedScope(UUID tenantId, UUID clientId, UUID authorizationId, String scope) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_scopes (tenant_id, client_id, authorization_id, scope, granted_at)
				VALUES (:tenantId, :clientId, :authorizationId, :scope, :grantedAt)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("authorizationId", authorizationId)
			.param("scope", scope)
			.param("grantedAt", ISSUED_AT)
			.update();
	}

	private void insertPrincipalAuthority(UUID tenantId, UUID clientId, UUID authorizationId, String authority) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_principal_authorities
				    (tenant_id, client_id, authorization_id, authority)
				VALUES (:tenantId, :clientId, :authorizationId, :authority)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("authorizationId", authorizationId)
			.param("authority", authority)
			.update();
	}

	private void insertToken(UUID tenantId, UUID clientId, UUID authorizationId, UUID tokenId, String tokenType,
			byte[] digest, byte[] initializationVector, byte[] ciphertext, String accessTokenType, String claims) {
		insertToken(tenantId, clientId, authorizationId, tokenId, tokenType, digest, initializationVector, ciphertext,
				accessTokenType, claims, "test-v1");
	}

	private void insertToken(UUID tenantId, UUID clientId, UUID authorizationId, UUID tokenId, String tokenType,
			byte[] digest, byte[] initializationVector, byte[] ciphertext, String accessTokenType, String claims,
			String encryptionKeyId) {
		insertToken(tenantId, clientId, authorizationId, tokenId, "authorization_code", tokenType, digest,
				initializationVector, ciphertext, accessTokenType, claims, encryptionKeyId);
	}

	private void insertToken(UUID tenantId, UUID clientId, UUID authorizationId, UUID tokenId,
			String authorizationGrantType, String tokenType, byte[] digest, byte[] initializationVector,
			byte[] ciphertext, String accessTokenType, String claims, String encryptionKeyId) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_tokens
				    (token_id, tenant_id, client_id, authorization_id, authorization_grant_type,
				     token_type, token_digest,
				     encryption_key_id, initialization_vector, ciphertext, access_token_type,
				     claims_version, claims, issued_at, expires_at, created_at, updated_at)
				VALUES
				    (:tokenId, :tenantId, :clientId, :authorizationId, :authorizationGrantType,
				     :tokenType, :digest,
				     :encryptionKeyId, :initializationVector, :ciphertext, :accessTokenType,
				     CASE WHEN CAST(:claims AS text) IS NULL THEN NULL ELSE 1 END,
				     CAST(:claims AS jsonb), :issuedAt, :expiresAt, :issuedAt, :issuedAt)
				""")
			.param("tokenId", tokenId)
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("authorizationId", authorizationId)
			.param("authorizationGrantType", authorizationGrantType)
			.param("tokenType", tokenType)
			.param("digest", digest)
			.param("encryptionKeyId", encryptionKeyId)
			.param("initializationVector", initializationVector)
			.param("ciphertext", ciphertext)
			.param("accessTokenType", accessTokenType)
			.param("claims", claims)
			.param("issuedAt", ISSUED_AT)
			.param("expiresAt", ISSUED_AT.plusMinutes(5))
			.update();
	}

	private void insertTokenScope(UUID tenantId, UUID clientId, UUID authorizationId, UUID tokenId, String scope) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_token_scopes
				    (tenant_id, client_id, authorization_id, token_id, scope)
				VALUES (:tenantId, :clientId, :authorizationId, :tokenId, :scope)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("authorizationId", authorizationId)
			.param("tokenId", tokenId)
			.param("scope", scope)
			.update();
	}

	private void insertConsent(UUID tenantId, UUID clientId, UUID userId, String principalName) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_consents (tenant_id, client_id, user_id, principal_name)
				VALUES (:tenantId, :clientId, :userId, :principalName)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("userId", userId)
			.param("principalName", principalName)
			.update();
	}

	private void insertConsentAuthority(UUID tenantId, UUID clientId, UUID userId, String authority) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_consent_authorities
				    (tenant_id, client_id, user_id, authority)
				VALUES (:tenantId, :clientId, :userId, :authority)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("userId", userId)
			.param("authority", authority)
			.update();
	}

	private int count(String table) {
		return this.jdbcClient.sql("SELECT count(*) FROM " + table).query(Integer.class).single();
	}

	private static byte[] bytes(int length, byte value) {
		byte[] bytes = new byte[length];
		java.util.Arrays.fill(bytes, value);
		return bytes;
	}

}
