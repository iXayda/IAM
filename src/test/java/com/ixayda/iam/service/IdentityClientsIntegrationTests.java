package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityClientsIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:client-test", "internal:clients", UUID.randomUUID());
	@Autowired private IdentityClients clients;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserRoles bindings;
	@Autowired private JdbcClient jdbc;
	@Autowired private JdbcTemplate template;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private UUID resourceId;
	private UUID roleId;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
	}

	@AfterEach
	void removeFaultsAndReferences() {
		for (String table : List.of("oauth2_registered_client", "iam_client", "iam_client_allowed_role", "iam_security_audit")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS client_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS client_test_fault()").update();
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user_role,iam_user_resource_role_revision CASCADE").update();
	}

	@Test
	void officialProtocolConfigurationIsAuthoritativeAndQueriesNeverContainCredentials() {
		var result = this.clients.create(config("Cafe\u0301 😀"), AUDIT);
		var client = result.client();
		var nativeClient = registered().findById(client.id().toString());
		assertThat(result.secret()).matches("[A-Za-z0-9_-]{43}");
		assertThat(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(result.secret(), nativeClient.getClientSecret())).isTrue();
		assertThat(nativeClient.getClientSecret()).startsWith("{argon2}$argon2id$");
		assertThat(nativeClient.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(nativeClient.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(nativeClient.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(nativeClient.getClientSettings().isRequireAuthorizationConsent()).isFalse();
		assertThat(nativeClient.getTokenSettings().isReuseRefreshTokens()).isFalse();
		assertThat(nativeClient.getTokenSettings().getAuthorizationCodeTimeToLive()).isEqualTo(Duration.ofSeconds(60));
		assertThat(nativeClient.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofSeconds(300));
		assertThat(nativeClient.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(7));
		assertThat(nativeClient.getClientId()).isEqualTo(client.id().toString());
		assertThat(nativeClient.getClientName()).isEqualTo("Café 😀");
		assertThat(nativeClient.getClientIdIssuedAt()).isEqualTo(client.createdAt());
		assertThat(client.version()).isEqualTo(1);
		assertThat(this.clients.findById(client.id())).contains(client);
		assertThat(this.clients.search(null, 20, null).items()).containsExactly(client);
		assertThat(client.toString()).doesNotContain(result.secret(), nativeClient.getClientSecret());
		assertThat(result.toString()).isEqualTo("IdentityClientSecret[REDACTED]");
		assertThat(this.jdbc.sql("SELECT to_jsonb(r)::text FROM oauth2_registered_client r").query(String.class).single()).doesNotContain(result.secret());
		var event = this.jdbc.sql("SELECT actor,source,target_user_id,target_type,target_id,correlation_id FROM iam_security_audit WHERE action='client_created'").query().singleRow();
		assertThat(event).containsEntry("actor", AUDIT.actor()).containsEntry("source", AUDIT.source()).containsEntry("correlation_id", AUDIT.correlationId())
				.containsEntry("target_user_id", null).containsEntry("target_type", "client").containsEntry("target_id", client.id());
		assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list().toString()).doesNotContain(result.secret(), nativeClient.getClientSecret(), "Café");
	}

	@Test
	void officialReloadPreservesInstantsAcrossTimeZonesAndRestart() throws Exception {
		var result = this.clients.create(config("Orders web"), AUDIT);
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			var source = new SingleConnectionDataSource(connection, true);
			JdbcClient.create(source).sql("SET TIME ZONE 'Pacific/Auckland'").update();
			var reloaded = new JdbcRegisteredClientRepository(new JdbcTemplate(source)).findByClientId(result.client().id().toString());
			assertThat(reloaded).isEqualTo(registered().findById(result.client().id().toString()));
			assertThat(reloaded.getClientIdIssuedAt()).isEqualTo(result.client().createdAt());
		}
	}

	@Test
	void persistenceRejectsUnsupportedLogoutCallbacksWithoutChangingTheClient() {
		var client = this.clients.create(config("Web"), AUDIT).client();
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE oauth2_registered_client SET post_logout_redirect_uris='https://orders.example/logout' WHERE id=:id")
				.param("id", client.id().toString()).update()).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
		assertThat(registered().findById(client.id().toString()).getPostLogoutRedirectUris()).isEmpty();
	}

	@Test
	void minimalScopeDoesNotPermitRefreshAndConfigurationIsNormalizedWithoutChangingExactUris() {
		var config = new IdentityClientConfiguration("Orders web", this.resourceId,
				List.of("https://orders.example/callback?tenant=A%20B", "https://orders.example/Callback"), Set.of("openid"), Set.of());
		var client = this.clients.create(config, AUDIT).client();
		assertThat(client.configuration().redirectUris()).containsExactly("https://orders.example/Callback", "https://orders.example/callback?tenant=A%20B");
		assertThat(registered().findById(client.id().toString()).getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registered().findById(client.id().toString()).getPostLogoutRedirectUris()).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://localhost/callback", "http://app.example/callback", "//app.example/callback", "/callback", "https://user@app.example/cb", "https://app.example/cb#fragment", "https://app.example/cb#", "https://*.example/cb", "https://app.example/*", "https://app.example/cb,other", "https://app.example/cb with space", "https://app.example/回调", "https://app.example:0/cb", "https://app.example:65536/cb", "https://app.example:/cb", "https://app.example/%0a", "https://app.example/cb?x=%00", "https://app.example/%", "https:///cb", "" })
	void invalidRedirectsCannotCreatePartialClients(String redirect) {
		var before = snapshot();
		var config = new IdentityClientConfiguration("Web", this.resourceId, List.of(redirect), Set.of("openid"), Set.of());
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(config, AUDIT));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void invalidScopesListBoundsNamesOrMissingInputsCannotWriteClients() {
		var before = snapshot();
		for (Set<String> scopes : List.of(Set.<String>of(), Set.of("profile"), Set.of("openid", "email"), Set.of("OPENID"))) {
			assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(new IdentityClientConfiguration("Web", this.resourceId, List.of("https://app.example/cb"), scopes, Set.of()), AUDIT));
		}
		for (List<String> redirects : List.of(List.<String>of(), List.of("https://app.example/cb", "https://app.example/cb"),
				IntStream.range(0, 11).mapToObj(i -> "https://app.example/cb" + i).toList(), List.of("https://app.example/" + "a".repeat(1000)))) {
			assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(new IdentityClientConfiguration("Web", this.resourceId, redirects, Set.of("openid"), Set.of()), AUDIT));
		}
		var tooMany = IntStream.range(0, 101).mapToObj(i -> UUID.randomUUID()).collect(Collectors.toSet());
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(new IdentityClientConfiguration("Web", this.resourceId, List.of("https://app.example/cb"), Set.of("openid"), tooMany), AUDIT));
		for (String name : List.of("", " ", "x\n", "\ud800", "😀".repeat(129))) { assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(config(name), AUDIT)); }
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(null, AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.create(config("Web"), null));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void configurationChangesHaveIndependentVersionsAndEquivalentInputsAreNoOps() {
		var original = this.clients.create(config("Web"), AUDIT).client();
		var before = snapshot();
		assertThat(this.clients.updateConfiguration(original.id(), 1, config("Web"), AUDIT)).isEqualTo(original);
		assertThat(this.clients.setEnabled(original.id(), 1, true, AUDIT)).isEqualTo(original);
		assertThatThrownBy(() -> this.clients.updateConfiguration(original.id(), 2, config("New"), AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(before);
		var changed = this.clients.updateConfiguration(original.id(), 1, config("New"), AUDIT);
		assertThat(changed.version()).isEqualTo(2);
		assertThat(changed.createdAt()).isEqualTo(original.createdAt());
		assertThat(changed.secretRotatedAt()).isEqualTo(original.secretRotatedAt());
		assertThat(this.resources.findById(this.resourceId).orElseThrow().version()).isEqualTo(1);
		assertThat(this.roles.findById(this.roleId).orElseThrow().version()).isEqualTo(1);
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.rotateSecret(original.id(), 0, AUDIT));
		assertThatThrownBy(() -> this.clients.setEnabled(UUID.randomUUID(), 1, false, AUDIT)).isInstanceOf(java.util.NoSuchElementException.class);
	}

	@Test
	void rotationImmediatelyReplacesTheSecretWithoutEnablingADisabledClient() {
		var original = this.clients.create(config("Web"), AUDIT);
		this.clients.setEnabled(original.client().id(), 1, false, AUDIT);
		var replacement = this.clients.rotateSecret(original.client().id(), 2, AUDIT);
		String hash = registered().findById(original.client().id().toString()).getClientSecret();
		var encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		assertThat(encoder.matches(original.secret(), hash)).isFalse();
		assertThat(encoder.matches(replacement.secret(), hash)).isTrue();
		assertThat(replacement.secret()).isNotEqualTo(original.secret());
		assertThat(replacement.client().id()).isEqualTo(original.client().id());
		assertThat(replacement.client().version()).isEqualTo(3);
		assertThat(replacement.client().status()).isEqualTo(IdentityClient.Status.DISABLED);
		assertThat(replacement.client().secretRotatedAt()).isAfterOrEqualTo(original.client().secretRotatedAt());
		assertThat(this.clients.findById(original.client().id()).orElseThrow().toString()).doesNotContain(original.secret(), replacement.secret(), hash);
		assertThat(this.jdbc.sql("SELECT action FROM iam_security_audit WHERE target_type='client' ORDER BY recorded_at,id").query(String.class).list())
				.containsExactly("client_created", "client_disabled", "client_secret_rotated");
	}

	@Test
	void inactiveParentsOrNewRolesCannotBeIntroducedButExistingReferencesCanBeInspectedAndRemoved() {
		var client = this.clients.create(config("Web"), AUDIT).client();
		this.roles.setEnabled(this.roleId, 1, false, AUDIT);
		assertThatThrownBy(() -> this.clients.create(config("Other"), AUDIT)).isInstanceOf(IdentityClients.ClientConfigurationNotAllowedException.class);
		assertThat(this.clients.updateConfiguration(client.id(), 1, config("Renamed"), AUDIT).version()).isEqualTo(2);
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		assertThat(this.clients.findById(client.id())).isPresent();
		assertThatThrownBy(() -> this.clients.setEnabled(client.id(), 2, true, AUDIT)).isInstanceOf(IdentityClients.ClientConfigurationNotAllowedException.class);
		var noRoles = new IdentityClientConfiguration("Restricted", this.resourceId, List.of("https://orders.example/callback"), Set.of("openid"), Set.of());
		assertThat(this.clients.updateConfiguration(client.id(), 2, noRoles, AUDIT).version()).isEqualTo(3);
		assertThat(this.clients.setEnabled(client.id(), 3, false, AUDIT).status()).isEqualTo(IdentityClient.Status.DISABLED);
		assertThatThrownBy(() -> this.clients.create(noRoles, AUDIT)).isInstanceOf(IdentityClients.ClientConfigurationNotAllowedException.class);
	}

	@Test
	void crossResourceRolesAreRejectedAndExplicitResourceChangesReplaceOnlyTheClientsEdges() {
		UUID otherResource = this.resources.create("urn:other", "Other", AUDIT).id();
		UUID otherRole = this.roles.create(otherResource, "reader", "Reader", AUDIT).id();
		var client = this.clients.create(config("Web"), AUDIT).client();
		var wrong = new IdentityClientConfiguration("Web", this.resourceId, List.of("https://app.example/cb"), Set.of("openid"), Set.of(otherRole));
		assertThatThrownBy(() -> this.clients.updateConfiguration(client.id(), 1, wrong, AUDIT)).isInstanceOf(IdentityClients.ClientConfigurationNotAllowedException.class);
		var correct = new IdentityClientConfiguration("Other web", otherResource, List.of("https://other.example/cb"), Set.of("openid"), Set.of(otherRole));
		var changed = this.clients.updateConfiguration(client.id(), 1, correct, AUDIT);
		assertThat(changed.configuration()).isEqualTo(correct);
		assertThat(changed.version()).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT role_id FROM iam_client_allowed_role WHERE client_id=:id").param("id", client.id().toString()).query(UUID.class).list()).containsExactly(otherRole);
	}

	@Test
	void invalidForeignRoleReferencesAreRejectedWithoutLockingAnotherResourcesRole() throws Exception {
		UUID otherResource = this.resources.create("urn:other", "Other", AUDIT).id();
		UUID otherRole = this.roles.create(otherResource, "reader", "Reader", AUDIT).id();
		var wrong = new IdentityClientConfiguration("Web", this.resourceId, List.of("https://app.example/cb"), Set.of("openid"), Set.of(otherRole));
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			connection.setAutoCommit(false);
			try (var statement = connection.prepareStatement("SELECT id FROM iam_resource_role WHERE id=? FOR UPDATE")) { statement.setObject(1, otherRole); statement.executeQuery().close(); }
			try {
				var rejected = executor.submit(() -> {
					try { this.clients.create(wrong, AUDIT); return false; }
					catch (IdentityClients.ClientConfigurationNotAllowedException ex) { return true; }
				});
				assertThat(rejected.get(3, TimeUnit.SECONDS)).isTrue();
			}
			finally { connection.rollback(); }
		}
		var client = this.clients.create(config("Web"), AUDIT).client();
		assertThatThrownBy(() -> this.jdbc.sql("INSERT INTO iam_client_allowed_role(client_id,resource_id,role_id) VALUES (:client,:resource,:role)")
				.param("client", client.id().toString()).param("resource", this.resourceId).param("role", otherRole).update())
				.isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("foreign key constraint");
	}

	@ParameterizedTest
	@ValueSource(strings = { "target_user_id=gen_random_uuid()", "target_type=NULL", "target_id=NULL", "target_type='role'", "outcome='failure'" })
	void clientAuditRequiresTheClientObjectAndCannotMasqueradeAsAUserOrRole(String assignment) {
		this.clients.create(config("Web"), AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET " + assignment + " WHERE action='client_created'").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void concurrentEditsOfOneVersionHaveExactlyOneWinner() throws Exception {
		var client = this.clients.create(config("Web"), AUDIT).client();
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var futures = IntStream.range(0, 2).mapToObj(i -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.clients.updateConfiguration(client.id(), 1, config("Web " + i), AUDIT); return true; }
				catch (OptimisticLockingFailureException ex) { return false; }
			})).toList();
			start.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var future : futures) { outcomes.add(future.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.clients.findById(client.id()).orElseThrow().version()).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='client_updated'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void aCreatorWaitingForItsParentLockRechecksCommittedState() throws Exception {
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var holder = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var creator = executor.submit(() -> {
				try { this.clients.create(config("Web"), AUDIT); return false; }
				catch (IdentityClients.ClientConfigurationNotAllowedException ex) { return true; }
			});
			try { await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_resource WHERE id%'").query(Long.class).single() > 0); }
			finally { release.countDown(); }
			holder.get(10, TimeUnit.SECONDS);
			assertThat(creator.get(10, TimeUnit.SECONDS)).isTrue();
		}
		assertThat(this.clients.search(null, 20, null).items()).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "create-audit", "update-audit", "disable-audit", "rotate-audit", "create-deferred", "rotate-deferred", "create-native-suppressed", "create-native-altered", "update-native-suppressed", "rotate-native-suppressed", "create-state-suppressed", "update-state-altered", "create-role-suppressed", "update-role-suppressed" })
	void failedOrAlteredMandatoryWritesRollBackConfigurationStateSecretsAndAudit(String operation) {
		boolean creation = operation.startsWith("create");
		var original = creation ? null : this.clients.create(config("Web"), AUDIT).client();
		UUID extraRole = this.roles.create(this.resourceId, "writer", "Writer", AUDIT).id();
		var next = new IdentityClientConfiguration("Changed", this.resourceId, List.of("https://new.example/cb"), Set.of("openid"), Set.of(extraRole));
		var before = snapshot();
		String table = operation.contains("native") ? "oauth2_registered_client" : operation.contains("state") ? "iam_client" : operation.contains("role") ? "iam_client_allowed_role" : "iam_security_audit";
		String change = creation || table.equals("iam_security_audit") || table.equals("iam_client_allowed_role") ? "INSERT" : "UPDATE";
		String body = operation.endsWith("suppressed") ? "RETURN NULL;" : operation.endsWith("altered")
				? (table.equals("iam_client") ? "NEW.status='disabled'; RETURN NEW;" : "NEW.client_name='Altered'; RETURN NEW;") : "RAISE EXCEPTION 'test client failure';";
		boolean deferred = operation.endsWith("deferred");
		this.jdbc.sql("CREATE FUNCTION client_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER client_test_fault AFTER " : "CREATE TRIGGER client_test_fault BEFORE ") + change + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION client_test_fault()").update();
		assertThatThrownBy(() -> {
			if (creation) { this.clients.create(config("Web"), AUDIT); }
			else if (operation.startsWith("rotate")) { this.clients.rotateSecret(original.id(), 1, AUDIT); }
			else if (operation.startsWith("disable")) { this.clients.setEnabled(original.id(), 1, false, AUDIT); }
			else { this.clients.updateConfiguration(original.id(), 1, next, AUDIT); }
		}).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void outerRollbackLeavesNoClientOrSecretHash() {
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> { this.clients.create(config("Web"), AUDIT); tx.setRollbackOnly(); });
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void publicReadsSeeConfigurationAndEdgesFromOneStatementSnapshot() throws Exception {
		var original = this.clients.create(config("Web"), AUDIT).client();
		var noRoles = new IdentityClientConfiguration("New", this.resourceId, List.of("https://other.example/cb"), Set.of("openid"), Set.of());
		var written = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.clients.updateConfiguration(original.id(), 1, noRoles, AUDIT);
				written.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			try { assertThat(written.await(5, TimeUnit.SECONDS)).isTrue(); assertThat(this.clients.findById(original.id())).contains(original); }
			finally { release.countDown(); }
			writer.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.clients.findById(original.id()).orElseThrow().configuration()).isEqualTo(noRoles);
	}

	@Test
	void pagingStatusAndDatabaseIdentityConstraintsPreserveStableClients() {
		var first = this.clients.create(config("First"), AUDIT).client();
		this.clients.create(config("Second"), AUDIT);
		var page = this.clients.search(null, 1, null);
		assertThat(page.items()).containsExactly(first);
		assertThat(this.clients.search(null, 100, page.nextCursor()).items()).hasSize(1).doesNotContain(first);
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.search(IdentityClient.Status.ACTIVE, 1, page.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.search(null, 101, null));
		this.clients.setEnabled(first.id(), 1, false, AUDIT);
		assertThat(this.clients.search(IdentityClient.Status.DISABLED, 20, null).items()).extracting(IdentityClient::id).containsExactly(first.id());
		for (String sql : List.of("DELETE FROM oauth2_registered_client", "DELETE FROM iam_client", "UPDATE oauth2_registered_client SET client_id=gen_random_uuid()::text", "UPDATE oauth2_registered_client SET client_id_issued_at=clock_timestamp()", "UPDATE iam_client SET version=version", "UPDATE iam_client SET created_at=created_at - INTERVAL '1 second',version=version+1")) {
			assertThatThrownBy(() -> this.jdbc.sql(sql).update()).isInstanceOf(DataIntegrityViolationException.class);
		}
	}

	@Test
	void upgradingV24PreservesIdentitiesRolesBindingsAndAuditWithoutCreatingClients() throws Exception {
		UUID user = this.users.create("alice", "Alice", AUDIT).id();
		this.bindings.change(user, this.roleId, 0, true, AUDIT);
		String schema = "client_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("24").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				var tables = List.of("iam_user", "iam_resource", "iam_resource_role", "iam_user_resource_role_revision", "iam_user_role", "iam_security_audit");
				for (String table : tables) { copyRows(old, table); }
				var before = tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				var migration = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("25").load();
				assertThat(migration.migrate().migrationsExecuted).isEqualTo(1);
				assertThat(tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList()).isEqualTo(before);
				for (String table : List.of("iam_client", "iam_client_allowed_role", "oauth2_registered_client")) { assertThat(old.sql("SELECT count(*) FROM " + table).query(Long.class).single()).isZero(); }
				assertThat(migration.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private IdentityClientConfiguration config(String name) {
		return new IdentityClientConfiguration(name, this.resourceId, List.of("https://orders.example/callback"),
				Set.of("openid", "profile", "offline_access"), Set.of(this.roleId));
	}
	private JdbcRegisteredClientRepository registered() { return new JdbcRegisteredClientRepository(this.template); }
	private List<List<String>> snapshot() {
		return List.of("iam_client", "oauth2_registered_client", "iam_client_allowed_role", "iam_security_audit", "iam_resource", "iam_resource_role").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

}
