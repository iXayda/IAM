package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;

class JdbcOAuth2AuthorizationConsentServiceIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID SECOND_TENANT_ID =
			UUID.fromString("019cc62e-1cb3-7248-9c6d-bf35c07fa001");

	private static final UUID FIRST_USER_ID =
			UUID.fromString("019cc62e-1cb3-7248-9c6d-bf35c07fa002");

	private static final UUID SECOND_USER_ID =
			UUID.fromString("019cc62e-1cb3-7248-9c6d-bf35c07fa003");

	private static final UUID FIRST_CLIENT_ID =
			UUID.fromString("019cc62e-1cb3-7248-9c6d-bf35c07fa004");

	private static final UUID SECOND_CLIENT_ID =
			UUID.fromString("019cc62e-1cb3-7248-9c6d-bf35c07fa005");

	@Autowired
	private OAuth2AuthorizationConsentService consents;

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createFixtures() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'authorization-consent', 'Authorization Consent')
				""").param("tenantId", SECOND_TENANT_ID).update();
		insertUser(TenantId.DEFAULT.value(), FIRST_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);
		insertClient(TenantId.DEFAULT.value(), FIRST_CLIENT_ID, "consent-first");
		insertClient(SECOND_TENANT_ID, SECOND_CLIENT_ID, "consent-second");
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM oauth_authorization_consents WHERE client_id IN (:firstId, :secondId)")
			.param("firstId", FIRST_CLIENT_ID)
			.param("secondId", SECOND_CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM oauth_clients WHERE client_id IN (:firstId, :secondId)")
			.param("firstId", FIRST_CLIENT_ID)
			.param("secondId", SECOND_CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:firstId, :secondId)")
			.param("firstId", FIRST_USER_ID)
			.param("secondId", SECOND_USER_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID)
			.update();
	}

	@Test
	void atomicallyReplacesAuthoritiesAndProtectsAgainstStaleRemoval() {
		OAuth2AuthorizationConsent initial = OAuth2AuthorizationConsent
			.withId(FIRST_CLIENT_ID.toString(), FIRST_USER_ID.toString())
			.scope("openid")
			.authority(new SimpleGrantedAuthority("ROLE_APPROVER"))
			.build();

		this.consents.save(initial);

		assertThat(this.consents.findById(FIRST_CLIENT_ID.toString(), FIRST_USER_ID.toString())).isEqualTo(initial);
		assertThat(storedTenantId()).isEqualTo(TenantId.DEFAULT.value());
		assertThat(storedVersion()).isZero();

		OAuth2AuthorizationConsent updated = OAuth2AuthorizationConsent.from(initial)
			.authorities(authorities -> {
				authorities.clear();
				authorities.add(new SimpleGrantedAuthority("SCOPE_api.read"));
			})
			.build();
		this.consents.save(updated);

		assertThat(this.consents.findById(FIRST_CLIENT_ID.toString(), FIRST_USER_ID.toString())).isEqualTo(updated);
		assertThat(storedVersion()).isOne();
		this.consents.remove(initial);
		assertThat(this.consents.findById(FIRST_CLIENT_ID.toString(), FIRST_USER_ID.toString())).isEqualTo(updated);
		this.consents.remove(updated);
		assertThat(this.consents.findById(FIRST_CLIENT_ID.toString(), FIRST_USER_ID.toString())).isNull();
	}

	@Test
	void rejectsCrossTenantOrInactiveConsentOwners() {
		OAuth2AuthorizationConsent crossTenant = OAuth2AuthorizationConsent
			.withId(FIRST_CLIENT_ID.toString(), SECOND_USER_ID.toString())
			.scope("openid")
			.build();

		assertThatThrownBy(() -> this.consents.save(crossTenant))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization consent requires an active client, tenant, and user");

		this.jdbcClient.sql("UPDATE oauth_clients SET status = 'disabled' WHERE client_id = :clientId")
			.param("clientId", FIRST_CLIENT_ID)
			.update();
		OAuth2AuthorizationConsent inactive = OAuth2AuthorizationConsent
			.withId(FIRST_CLIENT_ID.toString(), FIRST_USER_ID.toString())
			.scope("openid")
			.build();
		assertThatThrownBy(() -> this.consents.save(inactive))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization consent requires an active client, tenant, and user");
	}

	@Test
	void treatsMalformedLookupIdentifiersAsNotFound() {
		assertThat(this.consents.findById("not-a-uuid", FIRST_USER_ID.toString())).isNull();
		assertThat(this.consents.findById(FIRST_CLIENT_ID.toString(), "not-a-uuid")).isNull();
		assertThat(this.consents.findById(null, null)).isNull();
	}

	private void insertUser(UUID tenantId, UUID userId) {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", tenantId)
			.param("userId", userId)
			.update();
	}

	private void insertClient(UUID tenantId, UUID clientId, String identifier) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type, authentication_method)
				VALUES (:clientId, :tenantId, :identifier, 'Consent Client', 'public', 'none')
				""")
			.param("clientId", clientId)
			.param("tenantId", tenantId)
			.param("identifier", identifier)
			.update();
	}

	private UUID storedTenantId() {
		return this.jdbcClient.sql("""
				SELECT tenant_id
				FROM oauth_authorization_consents
				WHERE client_id = :clientId AND user_id = :userId
				""")
			.param("clientId", FIRST_CLIENT_ID)
			.param("userId", FIRST_USER_ID)
			.query(UUID.class)
			.single();
	}

	private long storedVersion() {
		return this.jdbcClient.sql("""
				SELECT version
				FROM oauth_authorization_consents
				WHERE client_id = :clientId AND user_id = :userId
				""")
			.param("clientId", FIRST_CLIENT_ID)
			.param("userId", FIRST_USER_ID)
			.query(Long.class)
			.single();
	}

}
