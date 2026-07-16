package com.ixayda.iam.client.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.CharBuffer;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.client.ClientAuthenticationMethod;
import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientOperations;
import com.ixayda.iam.client.ClientRedirectUri;
import com.ixayda.iam.client.ClientRegistration;
import com.ixayda.iam.client.ClientScope;
import com.ixayda.iam.client.ClientTokenPolicy;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.CreateClientRequest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

class SpringSecurityRegisteredClientRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private final List<ClientId> clientsToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private ClientOperations clients;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private RegisteredClientRepository registeredClients;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.clientsToDelete.forEach(clientId -> this.jdbcClient
			.sql("DELETE FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", clientId.value())
			.update());
		this.tenantsToDelete.forEach(tenantId -> this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void exposesOnlyClientsOwnedByActiveTenants() {
		ClientRegistration registration = create(TenantId.DEFAULT, "spring-public", ClientType.PUBLIC);
		RegisteredClient found = this.registeredClients.findByClientId("spring-public");

		assertThat(found).isNotNull();
		assertThat(this.registeredClients.findById(registration.client().id().toString())).isEqualTo(found);
		assertThat(this.registeredClients.findById("not-a-uuid")).isNull();
		assertThat(this.registeredClients.findByClientId("invalid client")).isNull();
		assertThat(this.registeredClients.findByClientId("SPRING-PUBLIC")).isNull();

		this.clients.disable(TenantId.DEFAULT, registration.client().id());
		assertThat(this.registeredClients.findByClientId("spring-public")).isNull();

		Tenant secondTenant = createTenant("registered-client-tenant", "Registered Client Tenant");
		ClientRegistration tenantRegistration = create(secondTenant.id(), "tenant-disabled-client", ClientType.PUBLIC);
		this.tenants.disable(secondTenant.id());
		assertThat(this.registeredClients.findById(tenantRegistration.client().id().toString())).isNull();
		registration.close();
		tenantRegistration.close();
	}

	@Test
	void authenticatesAndUpgradesAClientSecretThroughTheOfficialProvider() {
		try (ClientRegistration registration = create(TenantId.DEFAULT, "spring-confidential", ClientType.CONFIDENTIAL)) {
			char[] rawSecret = registration.clientSecret().orElseThrow().copy();
			try {
				String bcrypt = "{bcrypt}" + new BCryptPasswordEncoder().encode(CharBuffer.wrap(rawSecret));
				setEncodedSecret(registration.client().id(), bcrypt);
				long version = storedVersion(registration.client().id());
				OffsetDateTime updatedAt = storedUpdatedAt(registration.client().id());
				ClientSecretAuthenticationProvider provider = clientSecretProvider();

				assertThatThrownBy(() -> provider.authenticate(authentication("spring-confidential", "wrong-secret")))
					.isInstanceOf(OAuth2AuthenticationException.class)
					.satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
						.isEqualTo("invalid_client"));
				Authentication authenticated = provider
					.authenticate(authentication("spring-confidential", CharBuffer.wrap(rawSecret)));

				assertThat(authenticated).isNotNull();
				assertThat(authenticated.isAuthenticated()).isTrue();
				String upgraded = storedEncodedSecret(registration.client().id());
				assertThat(upgraded).startsWith("{pbkdf2@SpringSecurity_v5_8}").isNotEqualTo(bcrypt);
				assertThat(this.passwordEncoder.matches(CharBuffer.wrap(rawSecret), upgraded)).isTrue();
				assertThat(storedVersion(registration.client().id())).isEqualTo(version);
				assertThat(storedUpdatedAt(registration.client().id())).isEqualTo(updatedAt);
			}
			finally {
				Arrays.fill(rawSecret, '\0');
			}
		}
	}

	@Test
	void rejectsExpiredSecretsThroughTheOfficialProvider() {
		try (ClientRegistration registration = create(TenantId.DEFAULT, "spring-expired", ClientType.CONFIDENTIAL)) {
			char[] rawSecret = registration.clientSecret().orElseThrow().copy();
			try {
				Instant issuedAt = Instant.parse("2025-01-01T00:00:00Z");
				this.jdbcClient.sql("""
						UPDATE oauth_clients
						SET created_at = :issuedAt,
						    updated_at = :issuedAt,
						    client_secret_issued_at = :issuedAt,
						    client_secret_expires_at = :expiresAt
						WHERE client_id = :clientId
						""")
					.param("issuedAt", OffsetDateTime.ofInstant(issuedAt, ZoneOffset.UTC))
					.param("expiresAt", OffsetDateTime.ofInstant(issuedAt.plusSeconds(86_400), ZoneOffset.UTC))
					.param("clientId", registration.client().id().value())
					.update();

				assertThatThrownBy(() -> clientSecretProvider()
					.authenticate(authentication("spring-expired", CharBuffer.wrap(rawSecret))))
					.isInstanceOf(OAuth2AuthenticationException.class)
					.satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
						.isEqualTo("invalid_client"));
			}
			finally {
				Arrays.fill(rawSecret, '\0');
			}
		}
	}

	@Test
	void restrictsSaveToCurrentSecretEncodingUpgrades() {
		try (ClientRegistration registration = create(TenantId.DEFAULT, "spring-upgrade", ClientType.CONFIDENTIAL)) {
			RegisteredClient current = this.registeredClients.findByClientId("spring-upgrade");
			String replacement = this.passwordEncoder.encode("replacement-secret");
			RegisteredClient changedName = RegisteredClient.from(current)
				.clientName("Changed Name")
				.clientSecret(replacement)
				.build();

			assertThatThrownBy(() -> this.registeredClients.save(changedName))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Only the client secret encoding may be upgraded");

			RegisteredClient staleUpgrade = RegisteredClient.from(current).clientSecret(replacement).build();
			String rotated = this.passwordEncoder.encode("rotated-secret");
			setEncodedSecret(registration.client().id(), rotated);
			this.registeredClients.save(staleUpgrade);
			assertThat(storedEncodedSecret(registration.client().id())).isEqualTo(rotated);
		}
	}

	private ClientRegistration create(TenantId tenantId, String identifier, ClientType type) {
		ClientAuthenticationMethod authenticationMethod = type == ClientType.PUBLIC
				? ClientAuthenticationMethod.NONE : ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		ClientRegistration registration = this.clients.create(tenantId,
				new CreateClientRequest(new ClientIdentifier(identifier), "Spring Security Client", type,
					authenticationMethod,
					Set.of(new ClientRedirectUri("https://client.example.test/callback")), Set.of(),
					Set.of(new ClientScope("openid")), ClientTokenPolicy.secureDefaults()));
		this.clientsToDelete.add(registration.client().id());
		return registration;
	}

	private Tenant createTenant(String slug, String displayName) {
		Tenant tenant = this.tenants.create(new CreateTenantRequest(slug, displayName));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private ClientSecretAuthenticationProvider clientSecretProvider() {
		ClientSecretAuthenticationProvider provider = new ClientSecretAuthenticationProvider(this.registeredClients,
				new InMemoryOAuth2AuthorizationService());
		provider.setPasswordEncoder(this.passwordEncoder);
		return provider;
	}

	private static OAuth2ClientAuthenticationToken authentication(String clientId, Object secret) {
		return new OAuth2ClientAuthenticationToken(clientId,
				org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret, Map.of());
	}

	private void setEncodedSecret(ClientId clientId, String encodedSecret) {
		this.jdbcClient.sql("UPDATE oauth_clients SET encoded_client_secret = :encodedSecret WHERE client_id = :clientId")
			.param("encodedSecret", encodedSecret)
			.param("clientId", clientId.value())
			.update();
	}

	private String storedEncodedSecret(ClientId clientId) {
		return this.jdbcClient.sql("SELECT encoded_client_secret FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", clientId.value())
			.query(String.class)
			.single();
	}

	private long storedVersion(ClientId clientId) {
		return this.jdbcClient.sql("SELECT version FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", clientId.value())
			.query(Long.class)
			.single();
	}

	private OffsetDateTime storedUpdatedAt(ClientId clientId) {
		return this.jdbcClient.sql("SELECT updated_at FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", clientId.value())
			.query(OffsetDateTime.class)
			.single();
	}

}
