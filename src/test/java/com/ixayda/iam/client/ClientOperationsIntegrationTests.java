package com.ixayda.iam.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.CharBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class ClientOperationsIntegrationTests extends ApplicationIntegrationTest {

	private static final ClientRedirectUri REDIRECT_URI =
			new ClientRedirectUri("https://client.example.test/oauth/callback");

	private static final ClientRedirectUri POST_LOGOUT_REDIRECT_URI =
			new ClientRedirectUri("https://client.example.test/logout/callback");

	private final List<ClientId> clientsToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private ClientOperations clients;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private PlatformTransactionManager transactionManager;

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
	void createsAndFindsPublicAndConfidentialClientsWithoutPersistingRawSecrets() {
		OAuthClient publicClient;
		try (ClientRegistration registration = this.clients.create(TenantId.DEFAULT,
				request("operations-public", ClientType.PUBLIC))) {
			publicClient = registration.client();
			this.clientsToDelete.add(publicClient.id());
			assertThat(registration.clientSecret()).isEmpty();
			assertThat(publicClient.secretMetadata()).isNull();
		}

		IssuedClientSecret issuedSecret;
		OAuthClient confidentialClient;
		try (ClientRegistration registration = this.clients.create(TenantId.DEFAULT,
				request("operations-confidential", ClientType.CONFIDENTIAL,
						new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true,
								Duration.ofHours(2))))) {
			confidentialClient = registration.client();
			this.clientsToDelete.add(confidentialClient.id());
			issuedSecret = registration.clientSecret().orElseThrow();
			char[] rawSecret = issuedSecret.copy();
			try {
				String encodedSecret = this.jdbcClient.sql("""
						SELECT encoded_client_secret
						FROM oauth_clients
						WHERE client_id = :clientId
						""")
					.param("clientId", confidentialClient.id().value())
					.query(String.class)
					.single();
				assertThat(this.passwordEncoder.matches(CharBuffer.wrap(rawSecret), encodedSecret)).isTrue();
				assertThat(encodedSecret).startsWith("{").doesNotContain(new String(rawSecret));
				assertThat(registration.toString()).doesNotContain(new String(rawSecret)).doesNotContain(encodedSecret);
				assertThat(confidentialClient.toString()).doesNotContain(new String(rawSecret)).doesNotContain(encodedSecret);
			}
			finally {
				Arrays.fill(rawSecret, '\0');
			}
		}

		assertThat(issuedSecret.isDestroyed()).isTrue();
		assertThat(confidentialClient.secretMetadata()).isNotNull();
		assertThat(Duration.between(confidentialClient.secretMetadata().issuedAt(),
				confidentialClient.secretMetadata().expiresAt())).isEqualTo(Duration.ofDays(90));
		assertThat(confidentialClient.supportsRefreshTokens()).isTrue();
		assertThat(confidentialClient.tokenPolicy().refreshTokenTtl()).isEqualTo(Duration.ofHours(2));
		assertThat(this.jdbcClient.sql("""
				SELECT refresh_tokens_enabled::text || '|' || refresh_token_ttl_seconds
				FROM oauth_clients
				WHERE client_id = :clientId
				""")
			.param("clientId", confidentialClient.id().value())
			.query(String.class)
			.single()).isEqualTo("true|7200");
		assertThat(this.clients.findById(TenantId.DEFAULT, publicClient.id())).contains(publicClient);
		assertThat(this.clients.findByIdentifier(confidentialClient.identifier())).contains(confidentialClient);
		assertThat(this.clients.findActiveByIdentifier(confidentialClient.identifier())).contains(confidentialClient);
	}

	@Test
	void createsAndLoadsClientCredentialsClients() {
		CreateClientRequest request = new CreateClientRequest(new ClientIdentifier("scim-service-client"),
				"SCIM Service Client", ClientType.CONFIDENTIAL, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				ClientAuthorizationGrant.CLIENT_CREDENTIALS, Set.of(), Set.of(),
				Set.of(new ClientScope("scim.read"), new ClientScope("scim.write")),
				ClientTokenPolicy.serviceDefaults());
		OAuthClient serviceClient;
		try (ClientRegistration registration = this.clients.create(TenantId.DEFAULT, request)) {
			serviceClient = registration.client();
			this.clientsToDelete.add(serviceClient.id());
			assertThat(registration.clientSecret()).isPresent();
		}

		assertThat(serviceClient.authorizationGrant()).isEqualTo(ClientAuthorizationGrant.CLIENT_CREDENTIALS);
		assertThat(serviceClient.redirectUris()).isEmpty();
		assertThat(serviceClient.postLogoutRedirectUris()).isEmpty();
		assertThat(serviceClient.supportsRefreshTokens()).isFalse();
		assertThat(this.clients.findById(TenantId.DEFAULT, serviceClient.id())).contains(serviceClient);
		assertThat(this.clients.findByIdentifier(serviceClient.identifier())).contains(serviceClient);
		assertThat(this.jdbcClient.sql("""
				SELECT authorization_grant_type
				FROM oauth_clients
				WHERE client_id = :clientId
				""")
			.param("clientId", serviceClient.id().value())
			.query(String.class)
			.single()).isEqualTo("client_credentials");
	}

	@Test
	void enforcesGlobalIdentifiersAcrossTenants() {
		Tenant secondTenant = createTenant("client-identifier-tenant", "Client Identifier Tenant");
		OAuthClient first = createPublic(TenantId.DEFAULT, "globally-unique");

		assertThatThrownBy(() -> this.clients.create(secondTenant.id(), request("globally-unique", ClientType.PUBLIC)))
			.isInstanceOf(ClientAlreadyExistsException.class)
			.extracting("identifier")
			.isEqualTo(first.identifier());
		assertThat(this.clients.findByIdentifier(first.identifier())).contains(first);
	}

	@Test
	void scopesLifecycleCommandsToAnActiveTenant() {
		Tenant secondTenant = createTenant("client-lifecycle-tenant", "Client Lifecycle Tenant");
		OAuthClient created = createPublic(TenantId.DEFAULT, "tenant-isolated-client");

		assertThat(this.clients.findById(secondTenant.id(), created.id())).isEmpty();
		assertThatThrownBy(() -> this.clients.disable(secondTenant.id(), created.id()))
			.isInstanceOf(ClientNotFoundException.class);

		OAuthClient disabled = this.clients.disable(TenantId.DEFAULT, created.id());
		assertThat(disabled.status()).isEqualTo(ClientStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(this.clients.findActiveByIdentifier(disabled.identifier())).isEmpty();
		assertThat(this.clients.disable(TenantId.DEFAULT, created.id())).isEqualTo(disabled);
		assertThatThrownBy(() -> this.clients.requireActive(TenantId.DEFAULT, created.id()))
			.isInstanceOf(ClientDisabledException.class);

		OAuthClient active = this.clients.activate(TenantId.DEFAULT, created.id());
		assertThat(active.status()).isEqualTo(ClientStatus.ACTIVE);
		assertThat(active.version()).isEqualTo(2);

		OAuthClient tenantClient = createPublic(secondTenant.id(), "disabled-tenant-client");
		this.tenants.disable(secondTenant.id());
		assertThatThrownBy(() -> this.clients.create(secondTenant.id(), request("blocked-client", ClientType.PUBLIC)))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.clients.requireActive(secondTenant.id(), tenantClient.id()))
			.isInstanceOf(TenantDisabledException.class);
	}

	@Test
	void convergesConcurrentStatusChanges() throws Exception {
		OAuthClient created = createPublic(TenantId.DEFAULT, "concurrent-client");
		int callers = 8;
		CountDownLatch ready = new CountDownLatch(callers);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<OAuthClient>> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(callers)) {
			for (int index = 0; index < callers; index++) {
				results.add(executor.submit(() -> {
					ready.countDown();
					start.await();
					return this.clients.disable(TenantId.DEFAULT, created.id());
				}));
			}
			boolean allReady;
			try {
				allReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(allReady).isTrue();

			List<OAuthClient> transitions = new ArrayList<>();
			for (Future<OAuthClient> result : results) {
				transitions.add(result.get(10, TimeUnit.SECONDS));
			}
			OAuthClient stored = this.clients.findById(TenantId.DEFAULT, created.id()).orElseThrow();
			assertThat(transitions).allMatch(stored::equals);
			assertThat(stored.status()).isEqualTo(ClientStatus.DISABLED);
			assertThat(stored.version()).isOne();
		}
	}

	@Test
	void requiresAReadWriteTransactionForTheActiveWriteGuard() {
		OAuthClient created = createPublic(TenantId.DEFAULT, "client-write-guard");

		assertThatThrownBy(() -> this.clients.requireActiveForWrite(TenantId.DEFAULT, created.id()))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = new TransactionTemplate(this.transactionManager);
		readOnly.setReadOnly(true);
		assertThatThrownBy(
				() -> readOnly.execute(status -> this.clients.requireActiveForWrite(TenantId.DEFAULT, created.id())))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readWrite = new TransactionTemplate(this.transactionManager);
		OAuthClient guarded =
				readWrite.execute(status -> this.clients.requireActiveForWrite(TenantId.DEFAULT, created.id()));
		assertThat(guarded).isEqualTo(created);
	}

	private OAuthClient createPublic(TenantId tenantId, String identifier) {
		try (ClientRegistration registration = this.clients.create(tenantId, request(identifier, ClientType.PUBLIC))) {
			OAuthClient client = registration.client();
			this.clientsToDelete.add(client.id());
			return client;
		}
	}

	private Tenant createTenant(String slug, String displayName) {
		Tenant tenant = this.tenants.create(new CreateTenantRequest(slug, displayName));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private static CreateClientRequest request(String identifier, ClientType type) {
		return request(identifier, type, ClientTokenPolicy.secureDefaults());
	}

	private static CreateClientRequest request(String identifier, ClientType type, ClientTokenPolicy tokenPolicy) {
		ClientAuthenticationMethod authenticationMethod = type == ClientType.PUBLIC
				? ClientAuthenticationMethod.NONE : ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		return new CreateClientRequest(new ClientIdentifier(identifier), "OAuth Client", type, authenticationMethod,
				Set.of(REDIRECT_URI), Set.of(POST_LOGOUT_REDIRECT_URI),
				Set.of(new ClientScope("openid"), new ClientScope("api.read")), tokenPolicy);
	}

}
