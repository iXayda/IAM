package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.credential.AuthorizationSecrets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

class IdentityProtocolCleanupIntegrationTests extends IdentityProtocolTestSupport {

	private static final IdentityProtocolCleanup.Limits LIMITS = new IdentityProtocolCleanup.Limits(2, 10, 10);
	@Autowired IdentityProtocolCleanup cleanup;
	@Autowired AuthorizationSecrets protection;
	@Autowired PostgreSQLContainer postgres;

	@BeforeEach
	void clearInteractions() { this.jdbc.sql("TRUNCATE iam_authorization_interaction").update(); }

	@AfterEach
	void removeCleanupFaults() {
		this.jdbc.sql("DROP TRIGGER IF EXISTS cleanup_test_fault ON iam_authorization_token_index").update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS cleanup_test_fault()").update();
	}

	@Test
	void previewIsReadOnlyAndCleanupRetainsActiveGrantsInteractionsAndAllAudits() {
		UUID expired = nativeGrant(Instant.now().minusSeconds(600)); UUID live = nativeGrant(Instant.now().plusSeconds(300));
		interaction(true); interaction(false); var before = snapshot();
		assertThat(this.cleanup.preview(LIMITS)).isEqualTo(new IdentityProtocolCleanup.Counts(1, 1)); assertThat(snapshot()).isEqualTo(before);
		assertThat(this.cleanup.cleanUp(LIMITS)).isEqualTo(new IdentityProtocolCleanup.Counts(1, 1));
		assertThat(this.authorizations.findById(expired)).isEmpty(); assertThat(this.authorizations.findById(live)).isPresent();
		assertThat(rows("iam_security_audit")).isEqualTo(before.getLast()); assertThat(rows("iam_authorization_interaction")).hasSize(1);
		assertThat(this.cleanup.cleanUp(LIMITS).total()).isZero();
	}

	@Test
	void maximumAndBatchBoundsApplyAcrossGrantAndInteractionKinds() {
		for (int i = 0; i < 5; i++) { nativeGrant(Instant.now().minusSeconds(600)); interaction(true); }
		var limits = new IdentityProtocolCleanup.Limits(2, 3, 10);
		assertThat(this.cleanup.preview(limits)).isEqualTo(new IdentityProtocolCleanup.Counts(3, 3));
		assertThat(this.cleanup.cleanUp(limits).total()).isEqualTo(3);
		assertThat(rows("oauth2_authorization").size() + rows("iam_authorization_interaction").size()).isEqualTo(7);
	}

	@Test
	void graceWindowAndTheLatestTokenExpiryMustBothHaveEnded() {
		UUID recent = nativeGrant(Instant.now().minusSeconds(300)); UUID expired = nativeGrant(Instant.now().minusSeconds(600));
		var old = this.authorizations.findById(expired).orElseThrow();
		this.authorizations.save(OAuth2Authorization.from(old.authorization()).accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"still-live-access", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300), Set.of("openid"))).build(), old.version());
		var before = snapshot(); assertThat(this.cleanup.cleanUp(LIMITS).total()).isZero(); assertThat(snapshot()).isEqualTo(before);
		assertThat(this.authorizations.findById(recent)).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "active", "revoked", "quarantined" })
	void familyLifetimeRetainsEverySpentDigestEvenAfterAccessAndIdleExpiry(String status) {
		UUID id = agedFamily(Instant.now().plusSeconds(60), true);
		if (!status.equals("active")) {
			new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				var stored = this.authorizations.lockForUse(id).orElseThrow();
				if (status.equals("revoked")) { this.refresh.revoke(stored); } else { this.refresh.quarantine(stored); }
			});
		}
		var before = snapshot(); assertThat(this.cleanup.cleanUp(LIMITS).total()).isZero(); assertThat(snapshot()).isEqualTo(before);
		assertThat(rows("iam_refresh_history")).hasSize(2);
	}

	@Test
	void completeExpiredFamiliesAndTheirWholeParentChainAreDeletedAtomically() {
		UUID id = agedFamily(Instant.now().minusSeconds(600), true); var audit = rows("iam_security_audit");
		assertThat(this.cleanup.preview(LIMITS).authorizations()).isEqualTo(1);
		assertThat(this.cleanup.cleanUp(LIMITS).authorizations()).isEqualTo(1);
		for (String table : List.of("oauth2_authorization", "iam_authorization_record", "iam_authorization_token_index", "iam_authorization_binding", "iam_authorization_binding_role", "iam_refresh_family", "iam_refresh_history")) {
			assertThat(rows(table)).as(table).isEmpty();
		}
		assertThat(rows("iam_security_audit")).isEqualTo(audit); assertThat(this.authorizations.findById(id)).isEmpty();
	}

	@Test
	void databaseStillRejectsPrematureFamilyAndHistoryDeletion() {
		agedFamily(Instant.now().plusSeconds(60), true); var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_refresh_history").update()).isInstanceOf(org.springframework.dao.DataAccessException.class);
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_refresh_family").update()).isInstanceOf(org.springframework.dao.DataAccessException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void suppressedNativeIndexDeleteRollsBackTheWholeBatchAndCanBeRetried() {
		agedFamily(Instant.now().minusSeconds(600), true); interaction(true); var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION cleanup_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$").update();
		this.jdbc.sql("CREATE TRIGGER cleanup_test_fault BEFORE DELETE ON iam_authorization_token_index FOR EACH ROW EXECUTE FUNCTION cleanup_test_fault()").update();
		assertThatThrownBy(() -> this.cleanup.cleanUp(LIMITS)).isInstanceOf(RuntimeException.class); assertThat(snapshot()).isEqualTo(before);
		removeCleanupFaults(); assertThat(this.cleanup.cleanUp(LIMITS).total()).isEqualTo(2);
	}

	@Test
	void statementTimeoutRollsBackItsBatchWithinTheTimeBudget() {
		nativeGrant(Instant.now().minusSeconds(600)); var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION cleanup_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN OLD; END; $$").update();
		this.jdbc.sql("CREATE TRIGGER cleanup_test_fault BEFORE DELETE ON iam_authorization_token_index FOR EACH ROW EXECUTE FUNCTION cleanup_test_fault()").update();
		long started = System.nanoTime();
		assertThatThrownBy(() -> this.cleanup.cleanUp(new IdentityProtocolCleanup.Limits(1, 1, 1))).isInstanceOf(RuntimeException.class);
		assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3)); assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void corruptEncryptedStateIsRetainedAndNeverSilentlyDiscarded() {
		UUID id = nativeGrant(Instant.now().minusSeconds(600));
		this.jdbc.sql("UPDATE oauth2_authorization SET attributes='enc:v1:corrupt' WHERE id=:id").param("id", id.toString()).update(); var before = snapshot();
		assertThatThrownBy(() -> this.cleanup.cleanUp(LIMITS)).isInstanceOf(IllegalStateException.class); assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void aConcurrentProtocolMutationIsSkippedThenItsCommittedStateIsReevaluated() throws Exception {
		UUID id = nativeGrant(Instant.now().minusSeconds(600)); var held = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var mutation = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				var stored = this.authorizations.lockForUse(id).orElseThrow(); held.countDown(); awaitLatch(release);
				this.authorizations.save(OAuth2Authorization.from(stored.authorization()).accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
						"concurrent-token", Instant.now(), Instant.now().plusSeconds(300), Set.of("openid"))).build(), stored.version());
			}));
			try {
				awaitLatch(held); long started = System.nanoTime(); assertThat(this.cleanup.cleanUp(LIMITS).total()).isZero();
				assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
			} finally { release.countDown(); }
			mutation.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.cleanup.cleanUp(LIMITS).total()).isZero(); assertThat(this.authorizations.findById(id).orElseThrow().authorization().getAccessToken().isActive()).isTrue();
	}

	@ParameterizedTest
	@CsvSource({ "protocol, 1", "protocol, 2", "authorization, 2", "record, 2" })
	void busyLeadingCandidatesDoNotBlockLaterCleanup(String lockKind, int batchSize) throws Exception {
		var candidates = new ArrayList<UUID>();
		for (int i = 0; i < batchSize * 2 + 3; i++) { candidates.add(nativeGrant(Instant.now().minusSeconds(600))); }
		candidates.sort(Comparator.comparing(UUID::toString));
		var busy = candidates.subList(0, batchSize * 2);
		var idle = candidates.subList(batchSize * 2, candidates.size());
		var held = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var owner = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				for (UUID id : busy) {
					if (lockKind.equals("protocol")) { this.authorizations.lockForUse(id).orElseThrow(); }
					else {
						String table = switch (lockKind) {
							case "authorization" -> "oauth2_authorization";
							case "record" -> "iam_authorization_record";
							default -> throw new IllegalArgumentException("Unknown test lock");
						};
						this.jdbc.sql("SELECT id FROM " + table + " WHERE id=:id FOR UPDATE")
								.param("id", id.toString()).query(String.class).single();
					}
				}
				held.countDown(); awaitLatch(release);
			}));
			try {
				awaitLatch(held);
				assertThat(this.cleanup.preview(LIMITS).authorizations()).isEqualTo(candidates.size());
				assertThat(this.cleanup.cleanUp(new IdentityProtocolCleanup.Limits(batchSize, 2, 5)).authorizations()).isEqualTo(2);
				for (UUID id : busy) { assertThat(this.authorizations.findById(id)).isPresent(); }
				for (UUID id : idle.subList(0, 2)) { assertThat(this.authorizations.findById(id)).isEmpty(); }
				assertThat(this.authorizations.findById(idle.getLast())).isPresent();
			} finally { release.countDown(); }
			owner.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.cleanup.cleanUp(LIMITS).authorizations()).isEqualTo(candidates.size() - 2);
		assertThat(this.cleanup.cleanUp(LIMITS).total()).isZero();
	}

	@Test
	void independentApplicationInstancesResumeCleanupAndRuntimeIdentityCannotUseIt() throws Exception {
		nativeGrant(Instant.now().minusSeconds(600));
		try (var application = application(this.postgres.getUsername(), true)) {
			assertThat(application.getBean(IdentityProtocolCleanup.class).cleanUp(LIMITS).authorizations()).isEqualTo(1);
		}
		try (var application = application(this.postgres.getUsername(), true)) { assertThat(application.getBean(IdentityProtocolCleanup.class).cleanUp(LIMITS).total()).isZero(); }
		String role = "cleanup_runtime_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " LOGIN PASSWORD 'isolated-test-password'").update();
		try (var application = application(role, false)) {
			assertThatIllegalStateException().isThrownBy(() -> application.getBean(IdentityProtocolCleanup.class).preview(LIMITS)).withMessageContaining("database owner");
			assertThatIllegalStateException().isThrownBy(() -> application.getBean(IdentityProtocolCleanup.class).cleanUp(LIMITS)).withMessageContaining("database owner");
		} finally { this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	@Test
	void outerTransactionsAndUnboundedSettingsAreRejectedBeforeMutation() {
		var before = snapshot(); new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> this.cleanup.cleanUp(LIMITS));
			assertThatIllegalStateException().isThrownBy(() -> this.cleanup.preview(LIMITS));
		});
		for (int[] values : List.of(new int[] {0, 100, 10}, new int[] {101, 1000, 10}, new int[] {10, 9, 10}, new int[] {1, 10001, 10}, new int[] {1, 10, 0}, new int[] {1, 10, 301})) {
			assertThatIllegalArgumentException().isThrownBy(() -> new IdentityProtocolCleanup.Limits(values[0], values[1], values[2]));
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	private UUID nativeGrant(Instant expiry) {
		UUID id = UUID.randomUUID();
		this.authorizations.save(OAuth2Authorization.withRegisteredClient(this.protocol.findActiveById(this.clientId.toString()).orElseThrow().registration())
				.id(id.toString()).principalName(this.userId.toString()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizedScopes(Set.of("openid"))
				.token(new OAuth2AuthorizationCode("cleanup-code-" + id, expiry.minusSeconds(60), expiry)).build(), 0);
		return id;
	}

	/** Model elapsed time only in this fixture; all constraints, deletion guards and new encrypted seals are active during cleanup. */
	private UUID agedFamily(Instant deadline, boolean spentParent) {
		String code = code(Set.of("openid", "profile", "offline_access")); var tokens = exchange(request(code, authenticatedClient(code)));
		if (spentParent) {
			var request = new org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken(tokens.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), java.util.Map.of());
			request.setDetails(new com.ixayda.iam.security.IdentityRefreshTokenProvider.RequestEvidence(UUID.randomUUID()));
			new com.ixayda.iam.security.IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions).authenticate(request);
		}
		var stored = stored(code); var family = this.refresh.findByAuthorization(stored.authorization()).orElseThrow();
		long seconds = ChronoUnit.SECONDS.between(deadline.truncatedTo(ChronoUnit.SECONDS), family.absoluteExpiresAt().truncatedTo(ChronoUnit.SECONDS));
		UUID id = family.authorizationId();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			var binding = this.bindings.findByAuthorization(stored.authorization()).orElseThrow();
			var times = new ArrayList<Instant>(List.of(binding.session().authenticatedAt(), binding.session().idleExpiresAt(), binding.session().absoluteExpiresAt(), binding.issuedAt(), binding.codeExpiresAt(),
					family.startedAt(), family.updatedAt(), family.idleExpiresAt(), family.absoluteExpiresAt()));
			String bindingValue = stored.authorization().getAttribute("iam.authorizationBinding"); String familyValue = stored.authorization().getAttribute("iam.refreshFamily");
			var replacements = new java.util.HashMap<String, String>();
			for (Instant time : times) { replacements.put(time.toString(), time.minusSeconds(seconds).toString()); }
			var pattern = java.util.regex.Pattern.compile(replacements.keySet().stream().map(java.util.regex.Pattern::quote).collect(java.util.stream.Collectors.joining("|")));
			bindingValue = pattern.matcher(bindingValue).replaceAll(match -> replacements.get(match.group()));
			familyValue = pattern.matcher(familyValue).replaceAll(match -> replacements.get(match.group()));
			var agedSession = new com.ixayda.iam.model.IdentityAuthorizationSession(binding.session().access(), binding.session().browserSessionId(), binding.session().authenticatedAt().minusSeconds(seconds), binding.session().idleExpiresAt().minusSeconds(seconds), binding.session().absoluteExpiresAt().minusSeconds(seconds));
			var builder = OAuth2Authorization.from(stored.authorization()).attribute("iam.authorizationBinding", bindingValue).attribute("iam.refreshFamily", familyValue)
					.attribute(java.security.Principal.class.getName(), this.bindings.projectPrincipal(agedSession));
			var oldCode = stored.authorization().getToken(OAuth2AuthorizationCode.class).getToken(); builder.token(new OAuth2AuthorizationCode(oldCode.getTokenValue(), oldCode.getIssuedAt().minusSeconds(seconds), oldCode.getExpiresAt().minusSeconds(seconds)), metadata -> metadata.putAll(stored.authorization().getToken(OAuth2AuthorizationCode.class).getMetadata()));
			var oldAccess = stored.authorization().getAccessToken().getToken(); builder.token(new OAuth2AccessToken(oldAccess.getTokenType(), oldAccess.getTokenValue(), oldAccess.getIssuedAt().minusSeconds(seconds), oldAccess.getExpiresAt().minusSeconds(seconds), oldAccess.getScopes()), metadata -> metadata.putAll(stored.authorization().getAccessToken().getMetadata()));
			var oldRefresh = stored.authorization().getRefreshToken().getToken(); builder.token(new OAuth2RefreshToken(oldRefresh.getTokenValue(), oldRefresh.getIssuedAt().minusSeconds(seconds), oldRefresh.getExpiresAt().minusSeconds(seconds)), metadata -> metadata.putAll(stored.authorization().getRefreshToken().getMetadata()));
			var oldId = stored.authorization().getToken(org.springframework.security.oauth2.core.oidc.OidcIdToken.class); if (oldId != null) { var token = oldId.getToken(); builder.token(new org.springframework.security.oauth2.core.oidc.OidcIdToken(token.getTokenValue(), token.getIssuedAt().minusSeconds(seconds), token.getExpiresAt().minusSeconds(seconds), token.getClaims()), metadata -> metadata.putAll(oldId.getMetadata())); }
			for (String table : List.of("iam_authorization_binding", "iam_refresh_family", "iam_refresh_history")) { this.jdbc.sql("ALTER TABLE " + table + " DISABLE TRIGGER USER").update(); }
			try {
				this.jdbc.sql("UPDATE iam_authorization_binding SET authenticated_at=authenticated_at-:shift::interval,idle_expires_at=idle_expires_at-:shift::interval,absolute_expires_at=absolute_expires_at-:shift::interval,issued_at=issued_at-:shift::interval,code_expires_at=code_expires_at-:shift::interval WHERE authorization_id=:id").param("shift", seconds + " seconds").param("id", id.toString()).update();
				this.jdbc.sql("UPDATE iam_refresh_family SET started_at=started_at-:shift::interval,updated_at=updated_at-:shift::interval,idle_expires_at=idle_expires_at-:shift::interval,absolute_expires_at=absolute_expires_at-:shift::interval WHERE authorization_id=:id").param("shift", seconds + " seconds").param("id", id.toString()).update();
				var histories = this.jdbc.sql("SELECT * FROM iam_refresh_history WHERE authorization_id=:id ORDER BY generation").param("id", id.toString()).query().listOfRows();
				for (var row : histories) {
					Instant issued = ((java.sql.Timestamp) row.get("issued_at")).toInstant().minusSeconds(seconds), expiry = ((java.sql.Timestamp) row.get("expires_at")).toInstant().minusSeconds(seconds);
					Instant consumed = row.get("consumed_at") == null ? null : ((java.sql.Timestamp) row.get("consumed_at")).toInstant().minusSeconds(seconds);
					String encoded = "iam:refresh-history:v1|" + id + "|" + row.get("digest") + "|" + row.get("generation") + "|" + row.get("parent_digest") + "|" + issued + "|" + expiry + "|" + consumed;
					this.jdbc.sql("UPDATE iam_refresh_history SET issued_at=issued_at-:shift::interval,expires_at=expires_at-:shift::interval,consumed_at=consumed_at-:shift::interval,seal=:seal WHERE digest=:digest").param("shift", seconds + " seconds").param("seal", this.protection.refreshHistorySeal(encoded)).param("digest", row.get("digest")).update();
				}
				this.authorizations.save(builder.build(), stored.version());
			} finally { for (String table : List.of("iam_authorization_binding", "iam_refresh_family", "iam_refresh_history")) { this.jdbc.sql("ALTER TABLE " + table + " ENABLE TRIGGER USER").update(); } }
		});
		this.bindings.findByAuthorization(this.authorizations.findById(id).orElseThrow().authorization()).orElseThrow();
		this.refresh.findByAuthorization(this.authorizations.findById(id).orElseThrow().authorization()).orElseThrow(); return id;
	}

	private void interaction(boolean expired) {
		this.jdbc.sql("INSERT INTO iam_authorization_interaction(id,handle_digest,owner_digest,original_authenticated_at,created_at,expires_at,request) SELECT gen_random_uuid(),:handle,:owner,0,instant,instant+INTERVAL '600 seconds','enc:v1:isolated' FROM (SELECT clock_timestamp()+:shift::interval AS instant) t")
				.param("handle", UUID.randomUUID().toString().replace("-", "").repeat(2)).param("owner", "a".repeat(64)).param("shift", expired ? "-601 seconds" : "0 seconds").update();
	}

	private org.springframework.context.ConfigurableApplicationContext application(String user, boolean owner) {
		return new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(java.util.Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", user, "spring.datasource.password", owner ? this.postgres.getPassword() : "isolated-test-password",
				"spring.flyway.enabled", "false", "iam.signing.key-file", SIGNING_KEY.toString(), "iam.authorization.key-file", AUTHORIZATION_KEY.toString())).run();
	}

	private List<List<String>> snapshot() { return List.of("oauth2_authorization", "iam_authorization_record", "iam_authorization_token_index", "iam_authorization_binding", "iam_authorization_binding_role", "iam_refresh_family", "iam_refresh_history", "iam_authorization_interaction", "iam_security_audit").stream().map(this::rows).toList(); }
	private List<String> rows(String table) { return this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list(); }
}
