package com.ixayda.iam.controller;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.AccountSetupTokens;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.dto.IdentityUserSetupCompletionRequest;
import com.ixayda.iam.model.AccountSetupContext;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserSetup;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityUserSetupCompletions;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUserStates;
import com.ixayda.iam.service.IdentityUsers;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.service.IdentityUserSetupCompletions.Result.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.browser.requests-per-second=1000", "iam.account-setup.cleanup-ms=3600000" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserSetupCompletionIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/account-setup/complete";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:setup-test", "internal:test", UUID.randomUUID());

	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityUserSetupCompletions completions;
	@Autowired private AccountSetupTokens tokens;
	@Autowired private PasswordHasher passwords;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit, iam_account_setup_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@Test
	void anonymousCompletionCommitsThePasswordProofActivationAndAuditsWithoutLoggingIn() throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			String session = cookie(csrf);
			var response = post(client, PATH, session, form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.body()).isEmpty();
			assertSecurityHeaders(response);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(this.users.findById(proof.userId()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(this.passwords.matches(PASSWORD, hash(proof.userId()))).isTrue();
			assertThat(proofStatus(proof.userId())).isEqualTo("consumed");
			var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE source = 'browser:account-setup'").query().listOfRows();
			assertThat(events).hasSize(2).allSatisfy(row -> assertThat(row.get("actor")).isEqualTo("user:" + proof.userId()));
			assertThat(events.stream().map(row -> row.get("action"))).containsExactlyInAnyOrder("initial_password_set", "account_setup_completed");
			assertThat(events.get(0).get("correlation_id")).isEqualTo(events.get(1).get("correlation_id"));
			assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list()).noneMatch(text -> text.contains(PASSWORD) || text.contains(proof.token()));
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			var login = post(client, "/login", session, credentials("alice", PASSWORD, csrf(get(client, "/api/csrf", session))));
			assertThat(login.statusCode()).isEqualTo(204);
			assertThat(get(client, "/api/me", cookie(login)).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/admin/me", cookie(login)).statusCode()).isEqualTo(403);
		}
	}

	@Test
	void completingAnotherAccountNeverChangesTheExistingSessionIdentity() throws Exception {
		var caller = proof("bobby");
		this.setups.complete(caller.userId(), caller.token(), PASSWORD, "internal:test", UUID.randomUUID());
		var target = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var login = post(client, "/login", cookie(csrf), credentials("bobby", PASSWORD, csrf(csrf)));
			assertThat(login.statusCode()).isEqualTo(204);
			String session = cookie(login);
			var response = post(client, PATH, session, form(target.userId().toString(), target.token(), PASSWORD, csrf(get(client, "/api/csrf", session))));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(get(client, "/api/me", session).body()).contains(caller.userId().toString(), "bobby").doesNotContain(target.userId().toString(), "alice");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing-user", "missing-token", "empty-user", "empty-token", "spaced-token", "padded-token" })
	void absentOrNoncanonicalProofFieldsUseTheSameDenialAndCountAgainstTheBudget(String scenario) throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			String id = scenario.equals("empty-user") ? "" : proof.userId().toString();
			String token = switch (scenario) {
				case "empty-token" -> "";
				case "spaced-token" -> " " + proof.token();
				case "padded-token" -> proof.token() + "=";
				default -> proof.token();
			};
			String body = form(id, token, PASSWORD, csrf(csrf));
			if (scenario.equals("missing-user")) { body = body.replace("userId=" + id + "&", ""); }
			if (scenario.equals("missing-token")) { body = body.replace("token=" + encode(token) + "&", ""); }
			var response = post(client, PATH, cookie(csrf), body);
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).isEqualTo("Invalid account setup credential");
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_account_setup_limit").query(Long.class).single()).isEqualTo(2);
			assertPending(proof);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "unknown", "wrong-user", "wrong-token", "expired", "cancelled", "replaced", "replayed", "disabled", "password", "malformed-id", "short-id", "malformed-token" })
	void invalidProofCasesHaveTheSameStatusBodyAndAnonymousAttribution(String scenario) throws Exception {
		var proof = proof("alice");
		String id = proof.userId().toString();
		String token = proof.token();
		switch (scenario) {
			case "unknown" -> id = UUID.randomUUID().toString();
			case "wrong-user" -> id = proof("bobby").userId().toString();
			case "wrong-token" -> token = this.tokens.generate();
			case "expired" -> expire(proof.userId());
			case "cancelled" -> this.setups.cancel(proof.userId(), SYSTEM);
			case "replaced" -> this.setups.issue(proof.userId(), SYSTEM);
			case "replayed" -> this.setups.complete(proof.userId(), token, PASSWORD, "internal:test", UUID.randomUUID());
			case "disabled" -> this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", proof.userId()).update();
			case "password" -> this.users.setInitialPassword(proof.userId(), PASSWORD, SYSTEM);
			case "malformed-id" -> id = "invalid";
			case "short-id" -> id = "1-1-1-1-1";
			case "malformed-token" -> token = "invalid";
			default -> throw new AssertionError(scenario);
		}
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(id, token, "weak", csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).isEqualTo("Invalid account setup credential");
			assertSecurityHeaders(response);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'account_setup_failed'").query(String.class).single()).isEqualTo("anonymous");
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_account_setup_limit").query(Long.class).single()).isEqualTo(2);
			assertThat(count("account_setup_completed")).isZero();
		}
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "short", "passwordpassword", "                " })
	void invalidPasswordsPreserveTheProofAndAllowRetryWithinTheBudget(String password) throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			String body = "userId=" + proof.userId() + "&token=" + encode(proof.token()) + "&_csrf=" + encode(csrf(csrf));
			if (password != null) { body += "&password=" + encode(password); }
			var response = post(client, PATH, cookie(csrf), body);
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).isEqualTo("Password does not meet policy");
			assertPending(proof);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'account_setup_failed'").query(String.class).single()).isEqualTo("user:" + proof.userId());
			assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString().toUpperCase(java.util.Locale.ROOT), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(204);
			assertThat(this.jdbc.sql("SELECT failures FROM iam_account_setup_limit WHERE dimension = 'account'").query(Integer.class).single()).isZero();
			assertThat(this.jdbc.sql("SELECT failures FROM iam_account_setup_limit WHERE dimension = 'source'").query(Integer.class).single()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "&actor=system", "&source=trusted", "&code=123456", "&userId=other", "&token=other", "&password=other", "&_csrf=other" })
	void extraOrDuplicateFieldsAreRejectedBeforeConsumption(String extra) throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf)) + extra);
			assertThat(response.statusCode()).isEqualTo(400);
			assertPending(proof);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_account_setup_limit").query(Long.class).single()).isZero();
		}
	}

	@Test
	void contentTypeQueryCsrfMethodAndHeaderBindingBoundariesAreEnforced() throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			String session = cookie(csrf);
			String body = form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf));
			assertThat(post(client, PATH + "?userId=" + proof.userId(), session, body).statusCode()).isEqualTo(400);
			assertThat(post(client, PATH, session, body.replace("&_csrf=" + encode(csrf(csrf)), "")).statusCode()).isEqualTo(403);
			var json = HttpRequest.newBuilder(uri()).header("Cookie", session).header("Content-Type", "application/json")
					.header("X-CSRF-TOKEN", csrf(csrf)).POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			for (String method : List.of("GET", "PUT", "PATCH", "DELETE")) {
				var request = HttpRequest.newBuilder(uri()).header("Cookie", session).header("X-CSRF-TOKEN", csrf(csrf))
						.method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
			}
			var headers = HttpRequest.newBuilder(uri()).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(csrf)).header("userId", proof.userId().toString()).header("token", proof.token()).header("password", PASSWORD)
					.POST(HttpRequest.BodyPublishers.noBody()).build();
			assertThat(client.send(headers, HttpResponse.BodyHandlers.ofString()).body()).isEqualTo("Invalid account setup credential");
			assertPending(proof);
			var valid = HttpRequest.newBuilder(uri()).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(csrf)).POST(HttpRequest.BodyPublishers.ofString(body.replace("&_csrf=" + encode(csrf(csrf)), ""))).build();
			assertThat(client.send(valid, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
		}
	}

	@Test
	void accountBudgetCannotBeResetByReissuingAndDoesNotAlterLoginBudgets() {
		var proof = proof("alice");
		for (int i = 0; i < 5; i++) {
			assertThat(this.completions.complete(proof.userId().toString(), "invalid", PASSWORD, context("192.0.2.1"))).isEqualTo(INVALID_PROOF);
		}
		var replacement = this.setups.issue(proof.userId(), SYSTEM);
		assertThat(this.completions.complete(proof.userId().toString(), replacement.token(), PASSWORD, context("192.0.2.2"))).isEqualTo(THROTTLED);
		assertPending(proof);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit").query(Long.class).single()).isZero();
		this.jdbc.sql("UPDATE iam_account_setup_limit SET window_started_at = clock_timestamp() - INTERVAL '16 minutes'").update();
		assertThat(this.completions.complete(proof.userId().toString(), replacement.token(), PASSWORD, context("192.0.2.1"))).isEqualTo(COMPLETED);
	}

	@Test
	void httpBudgetReturns429WithoutConsumingAValidProof() throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			for (int i = 0; i < 5; i++) {
				assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString(), this.tokens.generate(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(400);
			}
			var response = post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(429);
			assertThat(response.body()).isEqualTo("Account setup temporarily unavailable");
			assertSecurityHeaders(response);
			assertPending(proof);
			assertThat(count("account_setup_failed")).isEqualTo(5);
			assertThat(count("account_setup_throttled")).isEqualTo(1);
		}
	}

	@Test
	void sourceBudgetBoundsUnknownAccountRowsAndIsSharedAcrossAddressRepresentations() throws Exception {
		for (int i = 0; i < 30; i++) {
			assertThat(this.completions.complete(UUID.randomUUID().toString(), "invalid", PASSWORD, context("192.0.2.1"))).isEqualTo(INVALID_PROOF);
		}
		var mapped = java.net.Inet6Address.getByAddress(null, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 255, (byte) 255, (byte) 192, 0, 2, 1 }, -1);
		assertThat(this.completions.complete(UUID.randomUUID().toString(), "invalid", PASSWORD,
				new AccountSetupContext("browser:account-setup", mapped, UUID.randomUUID()))).isEqualTo(THROTTLED);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_account_setup_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(30);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_account_setup_limit WHERE dimension = 'source'").query(Long.class).single()).isEqualTo(1);
		assertThat(count("account_setup_throttled")).isEqualTo(1);
	}

	@Test
	void malformedIdentifiersUseOneBoundedAccountBucketAndDtoTextHidesSecrets() {
		for (String id : List.of("invalid", "1-1-1-1-1", "", "another")) {
			assertThat(this.completions.complete(id, "invalid", PASSWORD, context("192.0.2.1"))).isEqualTo(INVALID_PROOF);
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_account_setup_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(1);
		assertThat(new IdentityUserSetupCompletionRequest("private-id", "private-proof", "private-password").toString()).doesNotContain("private-id", "private-proof", "private-password");
		assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.completions.complete(null, null, null, context("192.0.2.1")))).withMessageContaining("independent transaction");
	}

	@Test
	void oneProofCanOnlyBeConsumedOnceAcrossDifferentSources() throws Exception {
		var proof = proof("alice");
		try (var executor = Executors.newFixedThreadPool(2)) {
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1")); });
			var second = executor.submit(() -> { start.await(); return this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.2")); });
			start.countDown();
			assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS))).containsExactlyInAnyOrder(COMPLETED, INVALID_PROOF);
			assertThat(count("account_setup_completed")).isEqualTo(1);
			assertThat(count("account_setup_failed")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "reissue", "cancel", "disable" })
	void waitingConsumersRecheckProofAndUserAfterConcurrentLifecycleChanges(String operation) throws Exception {
		var proof = proof("alice");
		try (var executor = Executors.newFixedThreadPool(2)) {
			var entered = new CountDownLatch(1);
			var release = new CountDownLatch(1);
			var mutation = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
				this.jdbc.sql("SELECT id FROM iam_user WHERE id = :id FOR UPDATE").param("id", proof.userId()).query(UUID.class).single();
				entered.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				switch (operation) {
					case "reissue" -> this.setups.issue(proof.userId(), SYSTEM);
					case "cancel" -> this.setups.cancel(proof.userId(), SYSTEM);
					case "disable" -> this.states.disable(proof.userId(), SYSTEM);
					default -> throw new AssertionError(operation);
				}
			}));
			assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
			var consumption = executor.submit(() -> this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1")));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0)").query(Boolean.class).single());
			}
			finally { release.countDown(); }
			mutation.get(15, TimeUnit.SECONDS);
			assertThat(consumption.get(15, TimeUnit.SECONDS)).isEqualTo(INVALID_PROOF);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password WHERE user_id = :id").param("id", proof.userId()).query(Long.class).single()).isZero();
			assertThat(count("account_setup_completed")).isZero();
			assertThat(count("account_setup_failed")).isEqualTo(1);
		}
	}

	@Test
	void requiredFailureAuditAndBudgetWritesMustCommitBeforeReturningADenial() {
		var proof = proof("alice");
		for (String table : List.of("iam_security_audit", "iam_account_setup_limit")) {
			this.jdbc.sql("CREATE FUNCTION setup_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
			this.jdbc.sql("CREATE TRIGGER setup_denial_fault BEFORE " + (table.equals("iam_security_audit") ? "INSERT" : "UPDATE") + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION setup_denial_fault()").update();
			try {
				assertThatThrownBy(() -> this.completions.complete(proof.userId().toString(), "invalid", PASSWORD, context("192.0.2.1"))).isInstanceOf(IllegalStateException.class);
			}
			finally { this.jdbc.sql("DROP FUNCTION setup_denial_fault() CASCADE").update(); }
			assertThat(count("account_setup_failed")).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_account_setup_limit").query(Long.class).single()).isZero();
			assertPending(proof);
		}
	}

	@Test
	void cleanupRemovesOldBudgetRowsWithoutRemovingLiveFailures() {
		this.completions.complete(UUID.randomUUID().toString(), "invalid", PASSWORD, context("192.0.2.1"));
		this.jdbc.sql("UPDATE iam_account_setup_limit SET window_started_at = clock_timestamp() - INTERVAL '2 days' WHERE dimension = 'account'").update();
		this.completions.cleanUpExpiredLimits();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_account_setup_limit WHERE dimension = 'account'").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT failures FROM iam_account_setup_limit WHERE dimension = 'source'").query(Integer.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@CsvSource({ "password,INSERT", "proof,UPDATE", "activation,UPDATE", "audit,INSERT", "limits,UPDATE" })
	void storageFailuresRollBackPasswordProofActivationAndSuccessAudit(String fault, String mutation) throws Exception {
		var proof = proof("alice");
		String table = switch (fault) {
			case "password" -> "iam_password";
			case "proof" -> "iam_user_setup";
			case "activation" -> "iam_user";
			case "audit" -> "iam_security_audit";
			case "limits" -> "iam_account_setup_limit";
			default -> throw new AssertionError(fault);
		};
		this.jdbc.sql("CREATE FUNCTION setup_completion_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected setup failure'; END $$").update();
		this.jdbc.sql("CREATE TRIGGER setup_completion_fault BEFORE " + mutation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION setup_completion_fault()").update();
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(503);
			assertSecurityHeaders(response);
			assertThat(response.body()).doesNotContain(PASSWORD, proof.token());
		}
		finally { this.jdbc.sql("DROP FUNCTION setup_completion_fault() CASCADE").update(); }
		assertPending(proof);
		assertThat(count("account_setup_completed")).isZero();
		assertThat(this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1"))).isEqualTo(COMPLETED);
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "proof", "activation", "audit" })
	void silentAndDeferredStorageFailuresCannotReportSuccess(String fault) throws Exception {
		var proof = proof("alice");
		String table = fault.equals("password") ? "iam_password" : fault.equals("proof") ? "iam_user_setup" : fault.equals("activation") ? "iam_user" : "iam_security_audit";
		String mutation = fault.equals("password") || fault.equals("audit") ? "INSERT" : "UPDATE";
		for (boolean deferred : List.of(false, true)) {
			this.jdbc.sql("CREATE FUNCTION setup_completion_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
					+ (deferred ? "RAISE EXCEPTION 'deferred setup failure';" : "RETURN NULL;") + " END $$").update();
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER setup_completion_fault AFTER " : "CREATE TRIGGER setup_completion_fault BEFORE ")
					+ mutation + " ON " + table + (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION setup_completion_fault()").update();
			try (var client = client()) {
				var csrf = get(client, "/api/csrf", null);
				assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(503);
			}
			finally { this.jdbc.sql("DROP FUNCTION setup_completion_fault() CASCADE").update(); }
			assertPending(proof);
			assertThat(count("account_setup_completed")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "old", "pending" })
	void anUnstoredActivationCannotCompleteOrClearTheFailureBudget(String fault) throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			String session = cookie(csrf);
			assertThat(post(client, PATH, session, form(proof.userId().toString(), "invalid", PASSWORD, csrf(csrf))).statusCode()).isEqualTo(400);
			var storedProof = this.jdbc.sql("SELECT * FROM iam_user_setup WHERE user_id = :id").param("id", proof.userId()).query().singleRow();
			var limits = this.jdbc.sql("SELECT * FROM iam_account_setup_limit ORDER BY dimension, subject_key").query().listOfRows();
			var audits = this.jdbc.sql("SELECT * FROM iam_security_audit ORDER BY recorded_at, id").query().listOfRows();
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_account_setup_limit").query(Long.class).single()).isEqualTo(2);
			String mutation = fault.equals("old") ? "RETURN OLD;" : "NEW.status = 'pending'; RETURN NEW;";
			this.jdbc.sql("CREATE FUNCTION setup_activation_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + mutation + " END $$").update();
			this.jdbc.sql("CREATE TRIGGER setup_activation_fault BEFORE UPDATE ON iam_user FOR EACH ROW EXECUTE FUNCTION setup_activation_fault()").update();
			String body = form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf));
			try {
				var response = post(client, PATH, session, body);
				assertThat(response.statusCode()).isEqualTo(503);
				assertSecurityHeaders(response);
				assertThat(response.body()).doesNotContain(PASSWORD, proof.token(), "injected", "password_hash");
			}
			finally { this.jdbc.sql("DROP FUNCTION setup_activation_fault() CASCADE").update(); }
			assertPending(proof);
			assertThat(this.jdbc.sql("SELECT * FROM iam_user_setup WHERE user_id = :id").param("id", proof.userId()).query().singleRow()).isEqualTo(storedProof);
			assertThat(this.jdbc.sql("SELECT * FROM iam_account_setup_limit ORDER BY dimension, subject_key").query().listOfRows()).isEqualTo(limits);
			assertThat(this.jdbc.sql("SELECT * FROM iam_security_audit ORDER BY recorded_at, id").query().listOfRows()).isEqualTo(audits);
			assertThat(post(client, PATH, session, body).statusCode()).isEqualTo(204);
			assertThat(this.users.findById(proof.userId()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(this.passwords.matches(PASSWORD, hash(proof.userId()))).isTrue();
			assertThat(proofStatus(proof.userId())).isEqualTo("consumed");
			assertThat(count("initial_password_set")).isEqualTo(1);
			assertThat(count("account_setup_completed")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT failures FROM iam_account_setup_limit WHERE dimension = 'account'").query(Integer.class).single()).isZero();
		}
	}

	@Test
	void sessionPersistenceFailurePreventsAnyCredentialMutation() throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			this.jdbc.sql("CREATE FUNCTION setup_session_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'session failed'; END $$").update();
			this.jdbc.sql("CREATE TRIGGER setup_session_fault BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION setup_session_fault()").update();
			try {
				assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(503);
			}
			finally { this.jdbc.sql("DROP FUNCTION setup_session_fault() CASCADE").update(); }
			assertPending(proof);
			assertThat(count("account_setup_completed")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "audit" })
	void expiryDuringWritingRollsBackAllMutationsAndPersistsOnlyTheDenial(String waitingAt) throws Exception {
		var proof = proof("alice");
		this.jdbc.sql("UPDATE iam_user_setup SET expires_at = clock_timestamp() + INTERVAL '2 seconds' WHERE user_id = :id").param("id", proof.userId()).update();
		try (var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173804)"); }
			String guard = waitingAt.equals("audit") ? "IF NEW.action <> 'account_setup_completed' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION setup_completion_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173804); RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER setup_completion_wait BEFORE INSERT ON " + (waitingAt.equals("audit") ? "iam_security_audit" : "iam_password") + " FOR EACH ROW EXECUTE FUNCTION setup_completion_wait()").update();
			var waiting = executor.submit(() -> this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1")));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))").param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT expires_at <= clock_timestamp() FROM iam_user_setup WHERE user_id = :id").param("id", proof.userId()).query(Boolean.class).single());
				blocker.rollback();
				assertThat(waiting.get(15, TimeUnit.SECONDS)).isEqualTo(INVALID_PROOF);
			}
			finally { blocker.rollback(); this.jdbc.sql("DROP FUNCTION setup_completion_wait() CASCADE").update(); }
			assertPending(proof);
			assertThat(count("account_setup_completed")).isZero();
			assertThat(count("initial_password_set")).isZero();
			assertThat(count("account_setup_failed")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_account_setup_limit").query(Long.class).single()).isEqualTo(2);
		}
	}

	@Test
	void migrationFromV17PreservesExistingIdentitiesProofsAndAudits() throws Exception {
		String schema = "setup_upgrade";
		var flyway = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target("17").load();
		flyway.migrate();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			connection.setSchema(schema);
			var isolated = JdbcClient.create(new SingleConnectionDataSource(connection, true));
			UUID id = UUID.randomUUID();
			isolated.sql("INSERT INTO iam_user(id,username,display_name) VALUES (:id,'before','Before')").param("id", id).update();
			isolated.sql("INSERT INTO iam_user_setup(user_id,token_digest,status,issued_at,expires_at) VALUES (:id,:digest,'issued',clock_timestamp(),clock_timestamp()+INTERVAL '30 minutes')")
					.param("id", id).param("digest", this.tokens.digest(this.tokens.generate())).update();
			isolated.sql("INSERT INTO iam_security_audit(id,action,target_user_id,actor,source,outcome,correlation_id) VALUES (:event,'account_setup_issued',:id,'system:upgrade','internal:test','success',:correlation)")
					.param("event", UUID.randomUUID()).param("id", id).param("correlation", UUID.randomUUID()).update();
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).load().migrate();
			assertThat(isolated.sql("SELECT username FROM iam_user WHERE id = :id").param("id", id).query(String.class).single()).isEqualTo("before");
			assertThat(isolated.sql("SELECT status FROM iam_user_setup WHERE user_id = :id").param("id", id).query(String.class).single()).isEqualTo("issued");
			assertThat(isolated.sql("SELECT count(*) FROM iam_account_setup_limit").query(Long.class).single()).isZero();
			assertThat(isolated.sql("SELECT count(*) FROM iam_password").query(Long.class).single()).isZero();
			assertThat(isolated.sql("SELECT action FROM iam_security_audit").query(String.class).single()).isEqualTo("account_setup_issued");
		}
		finally { this.jdbc.sql("DROP SCHEMA setup_upgrade CASCADE").update(); }
	}

	private IdentityUserSetup proof(String username) { return this.setups.issue(this.users.create(username, "Private Name", SYSTEM).id(), SYSTEM); }
	private static String form(String userId, String token, String password, String csrf) {
		return "userId=" + encode(userId) + "&token=" + encode(token) + "&password=" + encode(password) + "&_csrf=" + encode(csrf);
	}
	private URI uri() { return URI.create("https://localhost:" + this.port + PATH); }
	private String hash(UUID id) { return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", id).query(String.class).single(); }
	private String proofStatus(UUID id) { return this.jdbc.sql("SELECT status FROM iam_user_setup WHERE user_id = :id").param("id", id).query(String.class).single(); }
	private long count(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action AND source = 'browser:account-setup'").param("action", action).query(Long.class).single(); }
	private void assertPending(IdentityUserSetup proof) {
		assertThat(this.users.findById(proof.userId()).orElseThrow().status()).isEqualTo(IdentityUser.Status.PENDING);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password WHERE user_id = :id").param("id", proof.userId()).query(Long.class).single()).isZero();
		assertThat(proofStatus(proof.userId())).isEqualTo("issued");
	}
	private void expire(UUID id) { this.jdbc.sql("UPDATE iam_user_setup SET issued_at=clock_timestamp()-INTERVAL '31 minutes', expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE user_id=:id").param("id", id).update(); }
	private static AccountSetupContext context(String address) {
		try { return new AccountSetupContext("browser:account-setup", InetAddress.getByName(address), UUID.randomUUID()); }
		catch (java.net.UnknownHostException ex) { throw new IllegalArgumentException(ex); }
	}

}
