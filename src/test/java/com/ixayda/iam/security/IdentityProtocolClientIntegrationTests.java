package com.ixayda.iam.security;

import java.sql.DriverManager;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.ClientSecrets;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.repository.IdentityClientRepository;
import com.ixayda.iam.service.IdentityClients;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.IdentityProtocolClients.Snapshot;
import com.ixayda.iam.service.IdentityResourceRoles;
import com.ixayda.iam.service.IdentityResources;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityProtocolClientIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:protocol-client-test", "internal:protocol-clients", UUID.randomUUID());
	private static final OAuth2AuthorizationService NO_GRANTS = new OAuth2AuthorizationService() {
		@Override public void save(OAuth2Authorization authorization) { throw new AssertionError("Credential verification cannot save a grant"); }
		@Override public void remove(OAuth2Authorization authorization) { throw new AssertionError("Credential verification cannot remove a grant"); }
		@Override public OAuth2Authorization findById(String id) { throw new AssertionError("Credential verification cannot read a grant"); }
		@Override public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) { throw new AssertionError("Credential verification cannot read a grant"); }
	};
	@Autowired private IdentityClients clients;
	@Autowired private IdentityProtocolClients protocol;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private JdbcClient jdbc;
	@Autowired private JdbcTemplate template;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private ApplicationContext application;
	private UUID resourceId;
	private UUID roleId;
	private IdentityRegisteredClientRepository adapter;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
		this.adapter = new IdentityRegisteredClientRepository(this.protocol);
	}

	@AfterEach
	void removeReferences() { this.jdbc.sql("TRUNCATE oauth2_registered_client CASCADE").update(); }

	@Test
	void officialClientAuthenticationAcceptsTheManagedArgon2HashWithoutMutatingAnyStore() {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		String id = result.client().id().toString();
		var before = databaseSnapshot();
		var snapshot = this.protocol.findActiveById(id).orElseThrow();
		assertThat(snapshot.client()).isEqualTo(result.client());
		assertThat(snapshot.resource()).isEqualTo(this.resources.findById(this.resourceId).orElseThrow());
		assertThat(this.adapter.findById(id)).isEqualTo(snapshot.registration());
		assertThat(this.adapter.findByClientId(id)).isEqualTo(snapshot.registration());
		var authenticated = authenticate(id, result.secret());
		assertThat(authenticated.isAuthenticated()).isTrue();
		assertThat(authenticated.getRegisteredClient()).isEqualTo(snapshot.registration());
		assertThat(this.protocol.secretVerifier().upgradeEncoding(snapshot.registration().getClientSecret())).isFalse();
		assertThatThrownBy(() -> this.adapter.save(snapshot.registration())).isInstanceOf(UnsupportedOperationException.class);
		assertThatThrownBy(() -> this.adapter.save(null)).isInstanceOf(UnsupportedOperationException.class);
		assertThat(snapshot.toString()).doesNotContain(result.secret(), snapshot.registration().getClientSecret(), result.client().configuration().redirectUris().getFirst());
		assertThat(databaseSnapshot()).isEqualTo(before);
		assertThat(revalidate(snapshot)).contains(snapshot);
	}

	@Test
	void invalidIdentifiersAreMissingAndNoProtocolBeansCanEnableDefaultStores() {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		for (String value : List.of("", " ", id.toUpperCase(java.util.Locale.ROOT), "1-1-1-1-1", UUID.randomUUID().toString(), "private-input-' OR 1=1", "a".repeat(1000))) {
			assertThat(this.protocol.findActiveById(value)).isEmpty();
			assertThat(this.adapter.findById(value)).isNull();
			assertThat(this.adapter.findByClientId(value)).isNull();
		}
		assertThat(this.adapter.findById(null)).isNull();
		assertThat(this.adapter.findByClientId(null)).isNull();
		assertThat(this.application.getBeansOfType(RegisteredClientRepository.class)).isEmpty();
		assertThat(this.application.getBeansOfType(OAuth2AuthorizationService.class)).isEmpty();
	}

	@Test
	void onlyBasicAuthenticationWithTheCurrentSecretCanSucceed() {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		var before = databaseSnapshot();
		for (String secret : List.of("", "invalid", "a".repeat(43), result.secret() + "x", "a".repeat(100_000))) { assertInvalidClient(() -> authenticate(id, secret)); }
		assertInvalidClient(() -> authenticate(id, null));
		assertInvalidClient(() -> authenticate(UUID.randomUUID().toString(), result.secret()));
		assertInvalidClient(() -> provider().authenticate(new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_POST, result.secret(), Map.of())));
		assertThat(provider().authenticate(new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.NONE, null, Map.of()))).isNull();
		assertThat(databaseSnapshot()).isEqualTo(before);
		var previous = this.protocol.findActiveById(id).orElseThrow();
		var rotated = this.clients.rotateSecret(result.client().id(), 1, AUDIT);
		assertInvalidClient(() -> authenticate(id, result.secret()));
		assertThat(authenticate(id, rotated.secret()).isAuthenticated()).isTrue();
		assertThat(revalidate(previous)).isEmpty();
	}

	@Test
	void trustedNativeAuthenticationRemovesPresentedCredentialsAndCarriesTheExactClientSnapshot() {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		String id = result.client().id().toString();
		var before = databaseSnapshot();
		var provider = new IdentityClientAuthenticationProvider(this.protocol, NO_GRANTS);
		var request = new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, result.secret(), Map.of());
		request.setDetails("private-transport-marker");
		var authenticated = (OAuth2ClientAuthenticationToken) provider.authenticate(request);
		assertThat(authenticated.isAuthenticated()).isTrue();
		assertThat(authenticated.getCredentials()).isNull();
		assertThat(authenticated.getAuthorities()).isEmpty();
		assertThat(authenticated.getDetails()).isEqualTo(this.protocol.findActiveById(id).orElseThrow());
		assertThat(authenticated.toString()).doesNotContain(result.secret(), "private-transport-marker", authenticated.getRegisteredClient().getClientSecret());
		assertThat(databaseSnapshot()).isEqualTo(before);
		assertThat(this.application.getBeansOfType(IdentityClientAuthenticationProvider.class)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "transfer", "secret" })
	void aSecretProofKeepsItsOriginalEpochsWhenManagementChangesDuringAuthentication(String mutation) {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		var previous = this.protocol.findActiveById(id).orElseThrow();
		var another = this.resources.create("urn:example:other", "Other", AUDIT);
		var watched = spy(this.protocol);
		doAnswer(call -> {
			var snapshot = call.callRealMethod();
			if (mutation.equals("transfer")) { this.clients.updateConfiguration(result.client().id(), 1, configuration(another.id(), Set.of()), AUDIT); }
			else { this.clients.rotateSecret(result.client().id(), 1, AUDIT); }
			return snapshot;
		}).when(watched).findActiveById(id);
		var provider = new IdentityClientAuthenticationProvider(watched, NO_GRANTS);
		var authenticated = (OAuth2ClientAuthenticationToken) provider.authenticate(new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, result.secret(), Map.of()));
		verify(watched, times(1)).findActiveById(id);
		assertThat(authenticated.getDetails()).isEqualTo(previous);
		assertThat(revalidate((Snapshot) authenticated.getDetails())).isEmpty();
		if (mutation.equals("transfer")) {
			assertThat(authenticated.getRegisteredClient()).isEqualTo(this.adapter.findById(id));
			assertThat(this.protocol.findActiveById(id).orElseThrow().resource().id()).isEqualTo(another.id());
		}
	}

	@Test
	void trustedClientAuthenticationHasUniformCredentialFailuresAndSanitizedStoreFailures() {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		var provider = new IdentityClientAuthenticationProvider(this.protocol, NO_GRANTS);
		for (var request : List.of(
				new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "private-invalid-secret", Map.of()),
				new OAuth2ClientAuthenticationToken(UUID.randomUUID().toString(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, result.secret(), Map.of()),
				new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_POST, result.secret(), Map.of()),
				new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.NONE, null, Map.of()))) {
			assertThatThrownBy(() -> provider.authenticate(request)).isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_client");
				assertThat(ex.getError().getDescription()).isEqualTo("Client authentication failed");
				assertThat(ex).hasNoCause();
			});
		}
		assertThat(provider.supports(OAuth2ClientAuthenticationToken.class)).isTrue();
		assertThat(provider.supports(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.class)).isFalse();
		assertThat(provider.authenticate(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.unauthenticated("user", "private-secret"))).isNull();
		this.jdbc.sql("UPDATE oauth2_registered_client SET token_settings='private-store-marker' WHERE id=:id").param("id", id).update();
		assertThatThrownBy(() -> provider.authenticate(new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, result.secret(), Map.of())))
				.isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> {
					assertThat(ex.getError().getErrorCode()).isEqualTo("server_error");
					assertThat(ex.getError().getDescription()).isEqualTo("Client authentication is unavailable");
					assertThat(ex).hasNoCause();
				});
	}

	@Test
	void disabledClientsAndResourcesCannotAuthenticateAndReenableDoesNotReviveAnOldSnapshot() {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		String id = result.client().id().toString();
		var previous = this.protocol.findActiveById(id).orElseThrow();
		this.clients.setEnabled(result.client().id(), 1, false, AUDIT);
		assertThat(this.adapter.findById(id)).isNull();
		assertInvalidClient(() -> authenticate(id, result.secret()));
		this.clients.setEnabled(result.client().id(), 2, true, AUDIT);
		assertThat(authenticate(id, result.secret()).isAuthenticated()).isTrue();
		assertThat(revalidate(previous)).isEmpty();
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		assertThat(this.adapter.findByClientId(id)).isNull();
		assertInvalidClient(() -> authenticate(id, result.secret()));
		this.resources.setEnabled(this.resourceId, 2, true, AUDIT);
		assertThat(authenticate(id, result.secret()).isAuthenticated()).isTrue();
		assertThat(revalidate(previous)).isEmpty();
	}

	@Test
	void resourceAndRoleConfigurationChangesAreDetectedEvenWhenNativeRegistrationIsIdentical() {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		String id = result.client().id().toString();
		var first = this.protocol.findActiveById(id).orElseThrow();
		this.clients.updateConfiguration(result.client().id(), 1, configuration(this.resourceId, Set.of()), AUDIT);
		var second = this.protocol.findActiveById(id).orElseThrow();
		assertThat(second.registration()).isEqualTo(first.registration());
		assertThat(second.client().configuration().allowedRoleIds()).isEmpty();
		assertThat(revalidate(first)).isEmpty();
		var another = this.resources.create("urn:example:other", "Other", AUDIT);
		this.clients.updateConfiguration(result.client().id(), 2, configuration(another.id(), Set.of()), AUDIT);
		var third = this.protocol.findActiveById(id).orElseThrow();
		assertThat(third.registration()).isEqualTo(second.registration());
		assertThat(third.resource().audience()).isEqualTo("urn:example:other");
		assertThat(revalidate(second)).isEmpty();
		assertThat(revalidate(third)).contains(third);
	}

	@Test
	void clientAuthenticationDoesNotTreatConfiguredRolesAsUserGrants() {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		String id = result.client().id().toString();
		this.roles.setEnabled(this.roleId, 1, false, AUDIT);
		var snapshot = this.protocol.findActiveById(id).orElseThrow();
		var authenticated = authenticate(id, result.secret());
		assertThat(authenticated.isAuthenticated()).isTrue();
		assertThat(authenticated.getAuthorities()).isEmpty();
		assertThat(snapshot.client().configuration().allowedRoleIds()).containsExactly(this.roleId);
		assertThat(this.roles.findById(this.roleId).orElseThrow().status()).isEqualTo(com.ixayda.iam.model.IdentityResourceRole.Status.DISABLED);
		assertThat(revalidate(snapshot)).contains(snapshot);
	}

	@ParameterizedTest
	@ValueSource(strings = { "pkce", "consent", "accessLifetime", "codeLifetime", "refreshLifetime", "reuse", "format", "algorithm", "clientSetting", "tokenSetting", "grant", "scope", "redirect", "hash" })
	void corruptedProtocolPolicyIsDeniedWithoutExposingSettingsOrCredentials(String invalid) {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		var original = this.adapter.findById(id);
		var changed = RegisteredClient.from(original);
		var clientSettings = ClientSettings.withSettings(original.getClientSettings().getSettings());
		var tokenSettings = TokenSettings.withSettings(original.getTokenSettings().getSettings());
		switch (invalid) {
			case "pkce" -> changed.clientSettings(clientSettings.requireProofKey(false).build());
			case "consent" -> changed.clientSettings(clientSettings.requireAuthorizationConsent(true).build());
			case "accessLifetime" -> changed.tokenSettings(tokenSettings.accessTokenTimeToLive(java.time.Duration.ofHours(1)).build());
			case "codeLifetime" -> changed.tokenSettings(tokenSettings.authorizationCodeTimeToLive(java.time.Duration.ofHours(1)).build());
			case "refreshLifetime" -> changed.tokenSettings(tokenSettings.refreshTokenTimeToLive(java.time.Duration.ofDays(8)).build());
			case "reuse" -> changed.tokenSettings(tokenSettings.reuseRefreshTokens(true).build());
			case "format" -> changed.tokenSettings(tokenSettings.accessTokenFormat(org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.REFERENCE).build());
			case "algorithm" -> changed.tokenSettings(tokenSettings.idTokenSignatureAlgorithm(SignatureAlgorithm.RS512).build());
			case "clientSetting" -> changed.clientSettings(clientSettings.setting("private-client-setting", "private-settings-marker").build());
			case "tokenSetting" -> changed.tokenSettings(tokenSettings.setting("private-token-setting", "private-settings-marker").build());
			case "grant" -> changed.authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS);
			case "scope" -> changed.scope("private-scope-marker");
			case "redirect" -> changed.redirectUri("https://app.example/private-marker/*");
			default -> changed.clientSecret(original.getClientSecret().replace("m=19456", "m=2147483647"));
		}
		new JdbcRegisteredClientRepository(this.template).save(changed.build());
		var before = databaseSnapshot();
		assertUnavailable(() -> this.adapter.findById(id));
		assertUnavailable(() -> authenticate(id, result.secret()));
		assertThat(databaseSnapshot()).isEqualTo(before);
	}

	@Test
	void malformedNativeJsonIsSanitizedAndAnOrphanNativeRegistrationIsNotAClient() {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		var registration = this.adapter.findById(id);
		String orphan = UUID.randomUUID().toString();
		var secrets = new ClientSecrets();
		new JdbcRegisteredClientRepository(this.template).save(RegisteredClient.withId(orphan).clientId(orphan).clientIdIssuedAt(registration.getClientIdIssuedAt())
				.clientName(registration.getClientName()).clientSecret(secrets.hash(secrets.generate())).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://app.example/cb").scope("openid").build());
		assertThat(this.adapter.findById(orphan)).isNull();
		this.jdbc.sql("UPDATE oauth2_registered_client SET client_settings='private-settings-marker' WHERE id=:id").param("id", id).update();
		var before = databaseSnapshot();
		assertUnavailable(() -> this.adapter.findById(id));
		assertThat(databaseSnapshot()).isEqualTo(before);
	}

	@Test
	void protocolRevalidationRequiresAnExistingWritableReadCommittedTransaction() {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		var snapshot = this.protocol.findActiveById(result.client().id().toString()).orElseThrow();
		assertThatIllegalStateException().isThrownBy(() -> this.protocol.lockForIssuance(snapshot));
		var readonly = new TransactionTemplate(this.transactions); readonly.setReadOnly(true);
		assertThatIllegalStateException().isThrownBy(() -> readonly.execute(tx -> this.protocol.lockForIssuance(snapshot)));
		for (int isolation : List.of(TransactionDefinition.ISOLATION_REPEATABLE_READ, TransactionDefinition.ISOLATION_SERIALIZABLE)) {
			var transaction = new TransactionTemplate(this.transactions); transaction.setIsolationLevel(isolation);
			assertThatIllegalStateException().isThrownBy(() -> transaction.execute(tx -> this.protocol.lockForIssuance(snapshot)));
		}
		// The actual database setting is checked even when Spring's transaction definition uses its default.
		assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> {
			this.jdbc.sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").update();
			return this.protocol.lockForIssuance(snapshot);
		}));
		assertThat(revalidate(snapshot)).contains(snapshot);
	}

	@ParameterizedTest
	@ValueSource(strings = { "secret", "client", "resource", "transfer", "roles" })
	void waitingForAnAdministrativeMutationRechecksTheCommittedSnapshot(String mutation) throws Exception {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		var snapshot = this.protocol.findActiveById(result.client().id().toString()).orElseThrow();
		var another = this.resources.create("urn:example:other", "Other", AUDIT);
		var changed = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					switch (mutation) {
						case "secret" -> this.clients.rotateSecret(result.client().id(), 1, AUDIT);
						case "client" -> this.clients.setEnabled(result.client().id(), 1, false, AUDIT);
						case "resource" -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
						case "transfer" -> this.clients.updateConfiguration(result.client().id(), 1, configuration(another.id(), Set.of()), AUDIT);
						default -> this.clients.updateConfiguration(result.client().id(), 1, configuration(this.resourceId, Set.of()), AUDIT);
					}
					changed.countDown(); awaitLatch(release);
				}));
				awaitLatch(changed);
				var reader = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-protocol-waiting-reader"); return this.protocol.lockForIssuance(snapshot);
				}));
				awaitLockWait("iam-protocol-waiting-reader");
				release.countDown();
				writer.get(10, TimeUnit.SECONDS);
				assertThat(reader.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void aFreshReadAfterNativeRowLockWaitCannotReuseTheOldCredential() throws Exception {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		var snapshot = this.protocol.findActiveById(result.client().id().toString()).orElseThrow();
		try (var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			blocker.setAutoCommit(false);
			try {
				try (var change = blocker.prepareStatement("UPDATE oauth2_registered_client SET client_secret=? WHERE id=?")) {
					var secrets = new ClientSecrets();
					change.setString(1, secrets.hash(secrets.generate())); change.setString(2, snapshot.registration().getId()); change.executeUpdate();
				}
				var reader = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-protocol-native-reader"); return this.protocol.lockForIssuance(snapshot);
				}));
				awaitLockWait("iam-protocol-native-reader");
				blocker.commit();
				assertThat(reader.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { blocker.rollback(); }
		}
	}

	@Test
	void parallelIssuersShareLocksWhileManagementWaitsForTheOuterCommit() throws Exception {
		var result = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		var snapshot = this.protocol.findActiveById(result.client().id().toString()).orElseThrow();
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var issuer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					assertThat(this.protocol.lockForIssuance(snapshot)).contains(snapshot); locked.countDown(); awaitLatch(release);
				}));
				awaitLatch(locked);
				var secondIssuer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> this.protocol.lockForIssuance(snapshot)));
				assertThat(secondIssuer.get(10, TimeUnit.SECONDS)).contains(snapshot);
				var administrator = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-protocol-waiting-admin"); return this.clients.rotateSecret(result.client().id(), 1, AUDIT);
				}));
				awaitLockWait("iam-protocol-waiting-admin");
				assertThat(administrator.isDone()).isFalse();
				release.countDown(); issuer.get(10, TimeUnit.SECONDS);
				assertThat(administrator.get(10, TimeUnit.SECONDS).client().version()).isEqualTo(2);
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void lostDatabaseReadPermissionsDenyTheNativeAdapterWithoutLeakingAnSqlCause() throws Exception {
		var result = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		String id = result.client().id().toString();
		String role = "protocol_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role).update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT ON oauth2_registered_client,iam_client,iam_resource,iam_client_allowed_role TO " + role).update();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
					var context = new AnnotationConfigApplicationContext()) {
				try (var statement = connection.createStatement()) { statement.execute("SET ROLE " + role); }
				var source = new SingleConnectionDataSource(connection, true);
				context.registerBean(JdbcClient.class, () -> JdbcClient.create(source));
				context.registerBean(JdbcTemplate.class, () -> new JdbcTemplate(source));
				context.register(IdentityClientRepository.class, IdentityProtocolClients.class, ClientSecrets.class);
				context.refresh();
				var restricted = new IdentityRegisteredClientRepository(context.getBean(IdentityProtocolClients.class));
				assertThat(restricted.findById(id)).isEqualTo(this.adapter.findById(id));
				this.jdbc.sql("REVOKE SELECT ON iam_client_allowed_role FROM " + role).update();
				assertUnavailable(() -> restricted.findByClientId(id));
			}
		}
		finally { this.jdbc.sql("DROP OWNED BY " + role).update(); this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	private IdentityClientConfiguration configuration(UUID resource, Set<UUID> allowedRoles) {
		return new IdentityClientConfiguration("Application", resource, List.of("https://app.example/cb"), Set.of("openid", "profile", "offline_access"), allowedRoles);
	}

	private Optional<Snapshot> revalidate(Snapshot snapshot) { return new TransactionTemplate(this.transactions).execute(tx -> this.protocol.lockForIssuance(snapshot)); }

	private ClientSecretAuthenticationProvider provider() {
		var provider = new ClientSecretAuthenticationProvider(this.adapter, NO_GRANTS);
		provider.setPasswordEncoder(this.protocol.secretVerifier());
		return provider;
	}

	private OAuth2ClientAuthenticationToken authenticate(String id, String secret) {
		return (OAuth2ClientAuthenticationToken) provider().authenticate(new OAuth2ClientAuthenticationToken(id, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret, Map.of()));
	}

	private List<String> databaseSnapshot() {
		return List.of("oauth2_registered_client", "iam_client", "iam_client_allowed_role", "iam_resource", "iam_security_audit").stream()
				.map(table -> table + this.jdbc.sql("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM " + table + " t").query(String.class).single()).toList();
	}

	private void applicationName(String value) { this.jdbc.sql("SELECT set_config('application_name',:name,true)").param("name", value).query(String.class).single(); }
	private void awaitLockWait(String name) {
		await().atMost(java.time.Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=:name AND wait_event_type='Lock')")
				.param("name", name).query(Boolean.class).single());
	}
	private static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Concurrent workflow did not reach its checkpoint"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	private static void assertInvalidClient(ThrowingCallable operation) {
		assertThatThrownBy(operation).isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_client"));
	}
	private static void assertUnavailable(ThrowingCallable operation) {
		assertThatThrownBy(operation).isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> {
			assertThat(ex.getError().getErrorCode()).isEqualTo("server_error");
			assertThat(ex.getError().getDescription()).isEqualTo("Client registration is unavailable");
			assertThat(ex).hasNoCause();
		});
	}

}
