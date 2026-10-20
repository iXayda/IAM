package com.ixayda.iam.security;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentitySigningKeyMetadata.Status;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentitySigningKeyIncidents;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;

class IdentitySigningKeyIncidentIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired private IdentitySigningKeyIncidents incidents;
	@Autowired private IdentityAccessTokens online;
	@Autowired private PostgreSQLContainer postgres;

	@AfterEach
	void cleanSigningStateAndFaults() {
		for (String table : List.of("iam_signing_key", "iam_signing_key_state")) { this.jdbc.sql("DROP TRIGGER IF EXISTS exchange_test_fault ON " + table).update(); }
		this.jdbc.sql("TRUNCATE iam_signing_key,iam_signing_key_state").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
	}

	@Test
	void activeCompromiseRevokesIssuedGrantsAndRefreshFamiliesWithoutChangingBrowserCredentialsOrUnusedCodes() {
		String grant = code(Set.of("openid", "offline_access")); var issued = exchange(request(grant, authenticatedClient(grant)));
		String unused = code(Set.of("openid")); var browser = this.store.findById(this.sessionId); var audit = incidentAudit();
		assertThat(this.incidents.compromise(this.signing.id(), audit)).isEqualTo(1);
		assertThat(this.keys.findPublicKey()).isEmpty(); assertThat(this.keys.verificationKeys()).isEmpty();
		assertThat(this.keys.metadata()).filteredOn(key -> key.id().equals(this.signing.id())).singleElement().satisfies(key -> {
			assertThat(key.status()).isEqualTo(Status.COMPROMISED); assertThat(key.compromisedAt()).isNotNull(); assertThat(key.verificationUntil()).isNull();
		});
		assertThat(new IdentityAccessTokenVerifier(this.online, "https://iam.example").verify(issued.getAccessToken().getTokenValue())).isEmpty();
		assertThat(IdentityAuthorizations.isRevoked(stored(grant).authorization())).isTrue();
		assertThat(this.refresh.findByAuthorization(stored(grant).authorization()).orElseThrow().status()).isEqualTo(IdentityRefreshFamily.Status.REVOKED);
		assertUnusedCode(unused);
		assertThat(this.store.findById(this.sessionId).getCreationTime()).isEqualTo(browser.getCreationTime());
		assertThat(this.users.hasCurrentPasswordVersion(this.userId, 1)).isTrue();
		assertThatIllegalStateException().isThrownBy(this.keys::initialize);
		assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
		assertThat(this.jdbc.sql("SELECT encrypted_private_key IS NULL AND protection_key_id IS NULL FROM iam_signing_key WHERE id=:id").param("id", this.signing.id()).query(Boolean.class).single()).isTrue();
		var events = this.jdbc.sql("SELECT action,target_type,target_id FROM iam_security_audit WHERE correlation_id=:id ORDER BY action").param("id", audit.correlationId()).query().listOfRows();
		assertThat(events).hasSize(2);
		assertThat(events.get(0)).containsEntry("action", "authorization_revoked").containsEntry("target_type", "authorization");
		assertThat(events.get(1)).containsEntry("action", "signing_key_compromised").containsEntry("target_id", this.signing.id()).containsEntry("target_type", "signing_key");
	}

	@Test
	void containmentRevokesMoreThanTheMaximumPageSizeAcrossMultipleUsers() {
		var codes = new java.util.ArrayList<String>();
		for (int user = 0; user < 2; user++) {
			if (user == 1) {
				this.userId = activeUser("bob"); this.assignments.change(this.userId, this.roleId, 0, true, AUDIT);
				this.sessionId = browserSession(this.userId, this.authenticatedAt);
			}
			for (int index = 0; index < 52; index++) {
				String code = code(Set.of("openid")); exchange(request(code, authenticatedClient(code))); codes.add(code);
			}
		}
		assertThat(this.incidents.compromise(this.signing.id(), incidentAudit())).isEqualTo(104);
		for (String code : codes) { assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue(); }
	}

	@Test
	void compromisingARetiredKeyFindsRefreshedGrantsThroughTheirHistoryAndPreservesIndependentNewGrants() {
		String original = code(Set.of("openid", "offline_access")); var first = exchange(request(original, authenticatedClient(original)));
		var retired = this.signing; this.signing = this.keys.rotate(retired.id(), incidentAudit());
		var renewed = refresh(first.getRefreshToken().getTokenValue());
		String independent = code(Set.of("openid")); var newer = exchange(request(independent, authenticatedClient(independent)));
		assertThat(stored(original).authorization().<String>getAttribute("iam.signingHistory")).contains(retired.id().toString(), this.signing.id().toString(), "complete");
		assertThat(this.incidents.compromise(retired.id(), incidentAudit())).isEqualTo(1);
		assertThat(this.keys.initialize()).contains(this.signing);
		var verifier = new IdentityAccessTokenVerifier(this.online, "https://iam.example");
		assertThat(verifier.verify(renewed.getAccessToken().getTokenValue())).isEmpty();
		assertThat(verifier.verify(newer.getAccessToken().getTokenValue())).isPresent();
		assertThat(this.keys.verificationKeys()).containsExactly(this.signing);
		assertThat(IdentityAuthorizations.isRevoked(stored(independent).authorization())).isFalse();
	}

	@Test
	void legacyIncompleteHistoryIsNeverPromotedToCompleteByRefreshAndIsConservativelyContained() {
		var old = this.signing; this.signing = this.keys.rotate(old.id(), incidentAudit());
		String legacy = code(Set.of("openid", "offline_access")); var first = exchange(request(legacy, authenticatedClient(legacy)));
		var current = stored(legacy); this.authorizations.save(OAuth2Authorization.from(current.authorization()).attributes(values -> values.remove("iam.signingHistory")).build(), current.version());
		this.signing = this.keys.rotate(this.signing.id(), incidentAudit()); refresh(first.getRefreshToken().getTokenValue());
		assertThat(stored(legacy).authorization().<String>getAttribute("iam.signingHistory")).contains("|partial|");
		assertThat(this.incidents.compromise(old.id(), incidentAudit())).isEqualTo(1);
		assertThat(IdentityAuthorizations.isRevoked(stored(legacy).authorization())).isTrue();
	}

	@Test
	void containmentDoesNotNeedTheCompromisedPrivateKeyAndExplicitRecoveryNeverRevivesOldGrants() throws Exception {
		String grant = code(Set.of("openid", "offline_access")); exchange(request(grant, authenticatedClient(grant)));
		String pending = code(Set.of("openid")); var original = this.signing;
		this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1) WHERE status='active'").update();
		this.incidents.compromise(original.id(), incidentAudit());
		var before = snapshot();
		assertThatIllegalStateException().isThrownBy(() -> this.keys.recover(UUID.randomUUID(), incidentAudit())); assertThat(snapshot()).isEqualTo(before);
		this.signing = this.keys.recover(original.id(), incidentAudit());
		assertThat(this.signing.id()).isNotEqualTo(original.id()); assertThat(this.keys.initialize()).contains(this.signing);
		assertThat(this.keys.verificationKeys()).containsExactly(this.signing);
		assertThat(IdentityAuthorizations.isRevoked(stored(grant).authorization())).isTrue();
		var issued = exchange(request(pending, authenticatedClient(pending))); verified(issued.getAccessToken().getTokenValue(), "at+jwt");
		assertThat(this.jdbc.sql("SELECT initial_key_id FROM iam_signing_key_state").query(UUID.class).single()).isEqualTo(original.id());
		before = snapshot();
		assertThatIllegalStateException().isThrownBy(() -> this.keys.recover(original.id(), incidentAudit())); assertThat(snapshot()).isEqualTo(before);
		assertThat(new IdentityJwkSource(this.keys).get(new JWKSelector(new JWKMatcher.Builder().keyID(original.id().toString()).build()), null)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "key-suppressed", "key-time-altered", "state-suppressed", "state-altered", "native-suppressed", "family-suppressed", "audit-suppressed", "audit-altered", "commit-rejected" })
	void containmentAndAllAffectedRevocationsAndAuditsRollBackTogetherOnStorageOrCommitFailure(String failure) {
		String grant = code(Set.of("openid", "offline_access")); exchange(request(grant, authenticatedClient(grant)));
		String other = code(Set.of("openid", "offline_access")); exchange(request(other, authenticatedClient(other))); var before = snapshot();
		String table = failure.startsWith("key-") ? "iam_signing_key" : failure.startsWith("state-") ? "iam_signing_key_state"
				: failure.startsWith("native-") ? "oauth2_authorization" : failure.startsWith("family-") ? "iam_refresh_family" : "iam_security_audit";
		String operation = table.equals("iam_security_audit") ? "INSERT" : "UPDATE";
		String body = switch (failure) {
			case "key-time-altered" -> "NEW.compromised_at := NEW.compromised_at+interval '1 second'; RETURN NEW;";
			case "state-altered" -> "NEW.revision := NEW.revision+1; RETURN NEW;";
			case "audit-suppressed" -> "IF NEW.action='signing_key_compromised' THEN RETURN NULL; END IF; RETURN NEW;";
			case "audit-altered" -> "NEW.target_id := gen_random_uuid(); RETURN NEW;";
			case "commit-rejected" -> "RAISE EXCEPTION 'isolated incident commit failure';";
			default -> "RETURN NULL;";
		};
		fault(table, (failure.equals("commit-rejected") ? "AFTER " : "BEFORE ") + operation, body, failure.equals("commit-rejected"));
		assertThatThrownBy(() -> this.incidents.compromise(this.signing.id(), incidentAudit())).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "key-suppressed", "state-suppressed", "audit-suppressed", "commit-rejected" })
	void failedReplacementLeavesSigningSuspendedAndTheCompromisedKeyTerminal(String failure) {
		this.incidents.compromise(this.signing.id(), incidentAudit()); var before = snapshot();
		String table = failure.startsWith("key-") ? "iam_signing_key" : failure.startsWith("state-") ? "iam_signing_key_state" : "iam_security_audit";
		fault(table, (failure.equals("commit-rejected") ? "AFTER " : "BEFORE ") + (table.equals("iam_signing_key_state") ? "UPDATE" : "INSERT"),
				failure.equals("commit-rejected") ? "RAISE EXCEPTION 'isolated recovery commit failure';" : "RETURN NULL;", failure.equals("commit-rejected"));
		assertThatThrownBy(() -> this.keys.recover(this.signing.id(), incidentAudit())).isInstanceOf(RuntimeException.class); assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void concurrentContainmentAndReplacementConfirmationsCommitOnlyOnce() throws Exception {
		var original = this.signing;
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> attemptContainment(original.id())); var second = executor.submit(() -> attemptContainment(original.id()));
			assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
			var recoverFirst = executor.submit(() -> attemptRecovery(original.id())); var recoverSecond = executor.submit(() -> attemptRecovery(original.id()));
			assertThat(List.of(recoverFirst.get(20, TimeUnit.SECONDS), recoverSecond.get(20, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.keys.metadata()).filteredOn(key -> key.status() == Status.ACTIVE).hasSize(1);
		assertThat(this.keys.metadata()).filteredOn(key -> key.status() == Status.COMPROMISED).hasSize(1);
	}

	@Test
	void anExchangeAlreadyHoldingTheSigningGateCommitsBeforeContainmentAndItsNewGrantIsIncluded() throws Exception {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code));
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_issued' THEN PERFORM pg_advisory_xact_lock(816372); END IF; RETURN NEW;", false);
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()); var executor = Executors.newFixedThreadPool(2)) {
			connection.setAutoCommit(false); try (var lock = connection.prepareStatement("SELECT pg_advisory_xact_lock(816372)")) { lock.executeQuery().close(); }
			var signing = executor.submit(() -> { serverContext("https://iam.example"); try { return exchange(request); } finally { AuthorizationServerContextHolder.resetContext(); } });
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE '%INSERT INTO iam_security_audit%'").query(Long.class).single() > 0);
				var containment = executor.submit(() -> this.incidents.compromise(this.signing.id(), incidentAudit()));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT initial_key_id%FROM iam_signing_key_state%FOR UPDATE'").query(Long.class).single() > 0);
				assertThat(containment.isDone()).isFalse(); connection.commit();
				assertThat(signing.get(10, TimeUnit.SECONDS).getAccessToken()).isNotNull();
				assertThat(containment.get(15, TimeUnit.SECONDS)).isEqualTo(1);
				assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue();
			}
			finally { connection.commit(); }
		}
	}

	@Test
	void incidentAndReplacementRejectAmbientTransactionsAndDatabaseWillNotReactivateACompromisedKey() {
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> this.incidents.compromise(this.signing.id(), incidentAudit()));
			assertThatIllegalStateException().isThrownBy(() -> this.keys.recover(this.signing.id(), incidentAudit()));
		});
		this.incidents.compromise(this.signing.id(), incidentAudit()); var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_signing_key SET status='retired',retired_at=compromised_at,verification_until=compromised_at+interval '330 seconds',compromised_at=NULL").update())
				.isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradingKeepsExistingKeysEncryptedProtocolStateAndAuditWithoutAddingARecoveryOrIncident() throws Exception {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code)));
		String schema = "signing_incident_upgrade_" + UUID.randomUUID().toString().replace("-", ""); this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("39").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema); var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				copyRows(old, "iam_user"); old.sql("INSERT INTO oauth2_registered_client SELECT * FROM public.oauth2_registered_client").update();
				old.sql("INSERT INTO oauth2_authorization SELECT * FROM public.oauth2_authorization").update();
				copyRows(old, "iam_authorization_record"); copyRows(old, "iam_authorization_token_index"); copyRows(old, "iam_security_audit"); copyRows(old, "iam_signing_key");
				old.sql("UPDATE iam_signing_key_state SET initial_key_id=:id,initialized_at=(SELECT created_at FROM iam_signing_key WHERE id=:id),active_key_id=:id,active_key_created_at=(SELECT created_at FROM iam_signing_key WHERE id=:id),revision=1")
						.param("id", this.signing.id()).update();
				var tables = List.of("iam_user", "oauth2_authorization", "iam_authorization_record", "iam_authorization_token_index", "iam_security_audit");
				var before = tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				var key = old.sql("SELECT to_jsonb(k)::text FROM iam_signing_key k").query(String.class).single();
				var lifecycle = old.sql("SELECT to_jsonb(s)::text FROM iam_signing_key_state s").query(String.class).single();
				var migration = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("40").load();
				assertThat(migration.migrate().migrationsExecuted).isEqualTo(1);
				assertThat(tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList()).isEqualTo(before);
				assertThat(old.sql("SELECT (to_jsonb(k)-'compromised_at')::text FROM iam_signing_key k").query(String.class).single()).isEqualTo(key);
				assertThat(old.sql("SELECT (to_jsonb(s)-'suspension_key_id')::text FROM iam_signing_key_state s").query(String.class).single()).isEqualTo(lifecycle);
				assertThat(migration.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private boolean attemptContainment(UUID id) { try { this.incidents.compromise(id, incidentAudit()); return true; } catch (IllegalStateException ex) { assertThat(ex).hasMessage("Signing key is already compromised"); return false; } }
	private boolean attemptRecovery(UUID id) { try { this.keys.recover(id, incidentAudit()); return true; } catch (IllegalStateException ex) { assertThat(ex).hasMessage("Signing key recovery does not match a suspended lifecycle"); return false; } }
	private static SecurityAuditContext incidentAudit() { return new SecurityAuditContext("deployment:operator-1", "deployment:signing-incident:CHANGE-123", UUID.randomUUID()); }
	private OAuth2AccessTokenAuthenticationToken refresh(String raw) {
		var request = new OAuth2RefreshTokenAuthenticationToken(raw, refreshClient(this.clientId, this.secret), Set.of(), java.util.Map.of());
		return (OAuth2AccessTokenAuthenticationToken) new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions).authenticate(request);
	}
	private void assertUnusedCode(String code) {
		assertThat(stored(code).version()).isEqualTo(1); assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isFalse(); assertThat(stored(code).authorization().getAccessToken()).isNull();
	}
	private List<List<String>> snapshot() {
		return List.of("iam_signing_key", "iam_signing_key_state", "oauth2_authorization", "iam_authorization_record", "iam_refresh_family", "iam_refresh_history", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}
}
