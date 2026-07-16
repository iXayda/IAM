package com.ixayda.iam.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
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

class OAuthClientSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID SECOND_TENANT_ID = UUID.fromString("019c73aa-b855-74f3-beb1-0d51587bc001");

	private static final UUID FIRST_CLIENT_ID = UUID.fromString("019c73aa-b855-74f3-beb1-0d51587bc002");

	private static final UUID SECOND_CLIENT_ID = UUID.fromString("019c73aa-b855-74f3-beb1-0d51587bc003");

	private static final UUID THIRD_CLIENT_ID = UUID.fromString("019c73aa-b855-74f3-beb1-0d51587bc004");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String ENCODED_SECRET = "{pbkdf2@SpringSecurity_v5_8}" + "a".repeat(96);

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createSecondTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'oauth-client-schema', 'OAuth Client Schema')
				""").param("tenantId", SECOND_TENANT_ID).update();
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient
			.sql("DELETE FROM oauth_clients WHERE client_id IN (:firstClientId, :secondClientId, :thirdClientId)")
			.param("firstClientId", FIRST_CLIENT_ID)
			.param("secondClientId", SECOND_CLIENT_ID)
			.param("thirdClientId", THIRD_CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void storesNormalizedTenantOwnedClientAggregates() {
		insertPublicClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "schema-public");
		insertConfidentialClient(SECOND_CLIENT_ID, SECOND_TENANT_ID, "schema-confidential", ENCODED_SECRET,
				CREATED_AT, CREATED_AT.plusSeconds(7_776_000));
		insertRedirect(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "https://public.example.test/callback");
		insertPostLogoutRedirect(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "https://public.example.test/logout");
		insertScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "openid");
		insertScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "api.read");

		assertThat(count("oauth_clients")).isEqualTo(2);
		assertThat(count("oauth_client_redirect_uris")).isOne();
		assertThat(count("oauth_client_post_logout_redirect_uris")).isOne();
		assertThat(count("oauth_client_scopes")).isEqualTo(2);
		assertThat(this.jdbcClient.sql("""
				SELECT collation_name
				FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name IN (
				      'oauth_clients', 'oauth_client_redirect_uris',
				      'oauth_client_post_logout_redirect_uris', 'oauth_client_scopes')
				  AND column_name IN (
				      'client_identifier', 'redirect_uri', 'post_logout_redirect_uri', 'scope')
				ORDER BY table_name
				""").query(String.class).list()).containsOnly("C");
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update()).isInstanceOf(DataIntegrityViolationException.class);

		this.jdbcClient.sql("DELETE FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", FIRST_CLIENT_ID)
			.update();
		assertThat(count("oauth_client_redirect_uris")).isZero();
		assertThat(count("oauth_client_post_logout_redirect_uris")).isZero();
		assertThat(count("oauth_client_scopes")).isZero();
	}

	@Test
	void enforcesGlobalCaseSensitiveIdentifiersAndTenantOwnership() {
		insertPublicClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "CaseSensitive");

		assertThatThrownBy(() -> insertPublicClient(SECOND_CLIENT_ID, SECOND_TENANT_ID, "CaseSensitive"))
			.isInstanceOf(DataIntegrityViolationException.class);
		insertPublicClient(SECOND_CLIENT_ID, SECOND_TENANT_ID, "casesensitive");
		assertThatThrownBy(() -> insertRedirect(SECOND_TENANT_ID, FIRST_CLIENT_ID,
				"https://cross-tenant.example.test/callback"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(count("oauth_clients")).isEqualTo(2);
	}

	@Test
	void rejectsInvalidClientAuthenticationAndSecretState() {
		assertThatThrownBy(() -> insertClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "public-with-secret",
				"public", "none", ENCODED_SECRET, CREATED_AT, CREATED_AT.plusSeconds(60)))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "confidential-no-secret",
				"confidential", "client_secret_basic", null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "confidential-noop",
				"confidential", "client_secret_basic", "{noop}" + "a".repeat(32), CREATED_AT,
				CREATED_AT.plusSeconds(60))).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "confidential-expired",
				"confidential", "client_secret_basic", ENCODED_SECRET, CREATED_AT, CREATED_AT))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "invalid-auth",
				"public", "client_secret_basic", null, null, null))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(count("oauth_clients")).isZero();
	}

	@Test
	void rejectsInvalidIdentifiersTokenLifetimesAndAggregateValues() {
		assertThatThrownBy(() -> insertPublicClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "invalid identifier"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type,
				     authentication_method, authorization_code_ttl_seconds, access_token_ttl_seconds)
				VALUES
				    (:clientId, :tenantId, 'invalid-ttl', 'Invalid TTL', 'public', 'none', 29, 3601)
				""")
			.param("clientId", FIRST_CLIENT_ID)
			.param("tenantId", TenantId.DEFAULT.value())
			.update()).isInstanceOf(DataIntegrityViolationException.class);

		insertPublicClient(FIRST_CLIENT_ID, TenantId.DEFAULT.value(), "aggregate-values");
		assertThatThrownBy(() -> insertRedirect(TenantId.DEFAULT.value(), FIRST_CLIENT_ID,
				"http://client.example.test/callback"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertRedirect(TenantId.DEFAULT.value(), FIRST_CLIENT_ID,
				"https://client.example.test/*"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertPostLogoutRedirect(TenantId.DEFAULT.value(), FIRST_CLIENT_ID,
				"https://client.example.test/logout#fragment"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "offline_access"))
			.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> insertScope(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "invalid scope"))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	private void insertPublicClient(UUID clientId, UUID tenantId, String identifier) {
		insertClient(clientId, tenantId, identifier, "public", "none", null, null, null);
	}

	private void insertConfidentialClient(UUID clientId, UUID tenantId, String identifier, String encodedSecret,
			Instant issuedAt, Instant expiresAt) {
		insertClient(clientId, tenantId, identifier, "confidential", "client_secret_basic", encodedSecret, issuedAt,
				expiresAt);
	}

	private void insertClient(UUID clientId, UUID tenantId, String identifier, String type,
			String authenticationMethod, String encodedSecret, Instant issuedAt, Instant expiresAt) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type,
				     authentication_method, encoded_client_secret, client_secret_issued_at,
				     client_secret_expires_at, created_at, updated_at)
				VALUES
				    (:clientId, :tenantId, :identifier, 'Schema Client', :clientType,
				     :authenticationMethod, :encodedSecret, CAST(:issuedAt AS timestamptz),
				     CAST(:expiresAt AS timestamptz), :createdAt, :createdAt)
				""")
			.param("clientId", clientId)
			.param("tenantId", tenantId)
			.param("identifier", identifier)
			.param("clientType", type)
			.param("authenticationMethod", authenticationMethod)
			.param("encodedSecret", encodedSecret)
			.param("issuedAt", offsetDateTime(issuedAt))
			.param("expiresAt", offsetDateTime(expiresAt))
			.param("createdAt", offsetDateTime(CREATED_AT))
			.update();
	}

	private void insertRedirect(UUID tenantId, UUID clientId, String redirectUri) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_client_redirect_uris (tenant_id, client_id, redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("redirectUri", redirectUri)
			.update();
	}

	private void insertPostLogoutRedirect(UUID tenantId, UUID clientId, String redirectUri) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_client_post_logout_redirect_uris
				    (tenant_id, client_id, post_logout_redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("redirectUri", redirectUri)
			.update();
	}

	private void insertScope(UUID tenantId, UUID clientId, String scope) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_client_scopes (tenant_id, client_id, scope)
				VALUES (:tenantId, :clientId, :scope)
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("scope", scope)
			.update();
	}

	private int count(String table) {
		return this.jdbcClient.sql("SELECT count(*) FROM " + table).query(Integer.class).single();
	}

	private static OffsetDateTime offsetDateTime(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

}
