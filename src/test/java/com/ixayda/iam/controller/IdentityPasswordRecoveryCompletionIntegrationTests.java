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
import com.ixayda.iam.credential.PasswordRecoveryTokens;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.dto.IdentityPasswordRecoveryCompletionRequest;
import com.ixayda.iam.model.PasswordRecoveryContext;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityPasswordRecovery;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityPasswordRecoveryCompletions;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityPasswordRecoveries;
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

import static com.ixayda.iam.service.IdentityPasswordRecoveryCompletions.Result.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.browser.requests-per-second=1000", "iam.password-recovery.cleanup-ms=3600000" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityPasswordRecoveryCompletionIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/password-recovery/complete";
	private static final String OLD_PASSWORD = "Seven amber lanterns beside the river";
	private static final String PASSWORD = "New violet lanterns above the lake";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:recovery-test", "internal:test", UUID.randomUUID());

	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityPasswordRecoveries recoveries;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityPasswordRecoveryCompletions completions;
	@Autowired private PasswordRecoveryTokens tokens;
	@Autowired private PasswordHasher passwords;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit, iam_password_recovery_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@Test
	void anonymousCompletionCommitsThePasswordProofRevocationAndAuditsWithoutLoggingIn() throws Exception {
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
			assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", proof.userId()).query(Long.class).single()).isEqualTo(2);
			var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE source = 'browser:password-recovery'").query().listOfRows();
			assertThat(events).hasSize(2).allSatisfy(row -> assertThat(row.get("actor")).isEqualTo("user:" + proof.userId()));
			assertThat(events.stream().map(row -> row.get("action"))).containsExactlyInAnyOrder("browser_sessions_revoked", "password_recovery_completed");
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

		var target = proof("alice");
		createSession("alice");
		createSession("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var login = post(client, "/login", cookie(csrf), credentials("bobby", OLD_PASSWORD, csrf(csrf)));
			assertThat(login.statusCode()).isEqualTo(204);
			String session = cookie(login);
			var response = post(client, PATH, session, form(target.userId().toString(), target.token(), PASSWORD, csrf(get(client, "/api/csrf", session))));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(targetSessionCount(target.userId())).isZero();
			assertThat(targetSessionCount(caller.userId())).isEqualTo(1);
			assertThat(get(client, "/api/me", session).body()).contains(caller.userId().toString(), "bobby").doesNotContain(target.userId().toString(), "alice");
		}
	}

	@Test
	void completingOwnRecoveryClearsCookieAndRevokesEverySessionWithoutSavingTheOldSessionAgain() throws Exception {
		var proof = proof("alice");
		String first = createSession("alice");
		String second = createSession("alice");
		try (var client = client()) {
			var response = post(client, PATH, first, form(proof.userId().toString(), proof.token(), PASSWORD, csrf(get(client, "/api/csrf", first))));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.headers().allValues("Set-Cookie")).singleElement().asString()
					.contains("__Host-IAMSESSION=", "Max-Age=0", "Path=/", "Secure", "HttpOnly", "SameSite=Lax");
			assertThat(targetSessionCount(proof.userId())).isZero();
			assertThat(proofStatus(proof.userId())).isEqualTo("consumed");
			for (String session : List.of(first, second)) { assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401); }
			assertThat(count("password_recovery_completed")).isEqualTo(1);
			assertThat(count("browser_sessions_revoked")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { OLD_PASSWORD, "Seven amber lanterns beside the Café", "Seven amber lanterns beside the Cafe\u0301" })
	void theCurrentPasswordIncludingCanonicalEquivalentsIsRejectedWithoutConsumingProof(String samePassword) throws Exception {
		var user = this.users.create("alice", "Alice", SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		String original = samePassword.equals(OLD_PASSWORD) ? OLD_PASSWORD : "Seven amber lanterns beside the Café";
		this.setups.complete(user.id(), setup.token(), original, "internal:test", UUID.randomUUID());
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String originalHash = hash(user.id());
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(user.id().toString(), proof.token(), samePassword, csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).isEqualTo("Password does not meet policy");
			assertThat(hash(user.id())).isEqualTo(originalHash);
			assertThat(proofStatus(user.id())).isEqualTo("issued");
			assertThat(post(client, PATH, cookie(csrf), form(user.id().toString(), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(204);
		}
	}

	@Test
	void recoveryBudgetsDoNotClearOrReuseOtherAuthenticationBudgets() {
		var proof = proof("alice");
		for (String table : List.of("iam_account_setup_limit", "iam_password_authentication_limit", "iam_totp_authentication_limit", "iam_mfa_recovery_limit")) {
			this.jdbc.sql("INSERT INTO " + table + " (dimension,subject_key,failures) VALUES ('account',repeat('a',64),1)").update();
		}
		assertThat(this.completions.complete(proof.userId().toString(), "invalid", PASSWORD, context("192.0.2.1"))).isEqualTo(INVALID_PROOF);
		assertThat(this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1"))).isEqualTo(COMPLETED);
		for (String table : List.of("iam_account_setup_limit", "iam_password_authentication_limit", "iam_totp_authentication_limit", "iam_mfa_recovery_limit")) {
			assertThat(this.jdbc.sql("SELECT failures FROM " + table).query(Integer.class).single()).isEqualTo(1);
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
			assertThat(response.body()).isEqualTo("Invalid password recovery credential");
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_password_recovery_limit").query(Long.class).single()).isEqualTo(2);
			assertOriginalPasswordAndIssuedProof(proof);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "unknown", "wrong-user", "wrong-token", "expired", "cancelled", "replaced", "replayed", "disabled", "version", "pending", "no-password", "wrong-purpose", "malformed-id", "short-id", "malformed-token" })
	void invalidProofCasesHaveTheSameStatusBodyAndAnonymousAttribution(String scenario) throws Exception {
		var proof = proof("alice");
		String id = proof.userId().toString();
		String token = proof.token();
		switch (scenario) {
			case "unknown" -> id = UUID.randomUUID().toString();
			case "wrong-user" -> id = proof("bobby").userId().toString();
			case "wrong-token" -> token = this.tokens.generate();
			case "expired" -> expire(proof.userId());
			case "cancelled" -> this.recoveries.cancel(proof.userId(), SYSTEM);
			case "replaced" -> this.recoveries.issue(proof.userId(), SYSTEM);
			case "replayed" -> this.recoveries.complete(proof.userId(), token, PASSWORD, "internal:test", UUID.randomUUID());
			case "disabled" -> this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", proof.userId()).update();
			case "version" -> this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id").param("id", proof.userId()).update();
			case "pending" -> this.jdbc.sql("UPDATE iam_user SET status = 'pending' WHERE id = :id").param("id", proof.userId()).update();
			case "no-password" -> this.jdbc.sql("DELETE FROM iam_password WHERE user_id = :id").param("id", proof.userId()).update();
			case "wrong-purpose" -> token = this.setups.issue(this.users.create("carol", "Carol", SYSTEM).id(), SYSTEM).token();
			case "malformed-id" -> id = "invalid";
			case "short-id" -> id = "1-1-1-1-1";
			case "malformed-token" -> token = "invalid";
			default -> throw new AssertionError(scenario);
		}
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(id, token, "weak", csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).isEqualTo("Invalid password recovery credential");
			assertSecurityHeaders(response);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'password_recovery_failed'").query(String.class).single()).isEqualTo("anonymous");
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_password_recovery_limit").query(Long.class).single()).isEqualTo(2);
			assertThat(count("password_recovery_completed")).isZero();
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
			if (password != null) { body += "&newPassword=" + encode(password); }
			var response = post(client, PATH, cookie(csrf), body);
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).isEqualTo("Password does not meet policy");
			assertOriginalPasswordAndIssuedProof(proof);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'password_recovery_failed'").query(String.class).single()).isEqualTo("user:" + proof.userId());
			assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString().toUpperCase(java.util.Locale.ROOT), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(204);
			assertThat(this.jdbc.sql("SELECT failures FROM iam_password_recovery_limit WHERE dimension = 'account'").query(Integer.class).single()).isZero();
			assertThat(this.jdbc.sql("SELECT failures FROM iam_password_recovery_limit WHERE dimension = 'source'").query(Integer.class).single()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "&actor=system", "&source=trusted", "&code=123456", "&userId=other", "&token=other", "&newPassword=other", "&password=other", "&_csrf=other" })
	void extraOrDuplicateFieldsAreRejectedBeforeConsumption(String extra) throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf)) + extra);
			assertThat(response.statusCode()).isEqualTo(400);
			assertOriginalPasswordAndIssuedProof(proof);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery_limit").query(Long.class).single()).isZero();
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
					.header("X-CSRF-TOKEN", csrf(csrf)).header("userId", proof.userId().toString()).header("token", proof.token()).header("newPassword", PASSWORD)
					.POST(HttpRequest.BodyPublishers.noBody()).build();
			assertThat(client.send(headers, HttpResponse.BodyHandlers.ofString()).body()).isEqualTo("Invalid password recovery credential");
			assertOriginalPasswordAndIssuedProof(proof);
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
		var replacement = this.recoveries.issue(proof.userId(), SYSTEM);
		assertThat(this.completions.complete(proof.userId().toString(), replacement.token(), PASSWORD, context("192.0.2.2"))).isEqualTo(THROTTLED);
		assertOriginalPasswordAndIssuedProof(proof);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit").query(Long.class).single()).isZero();
		this.jdbc.sql("UPDATE iam_password_recovery_limit SET window_started_at = clock_timestamp() - INTERVAL '16 minutes'").update();
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
			assertThat(response.body()).isEqualTo("Password recovery temporarily unavailable");
			assertSecurityHeaders(response);
			assertOriginalPasswordAndIssuedProof(proof);
			assertThat(count("password_recovery_failed")).isEqualTo(5);
			assertThat(count("password_recovery_throttled")).isEqualTo(1);
		}
	}

	@Test
	void sourceBudgetBoundsUnknownAccountRowsAndIsSharedAcrossAddressRepresentations() throws Exception {
		for (int i = 0; i < 30; i++) {
			assertThat(this.completions.complete(UUID.randomUUID().toString(), "invalid", PASSWORD, context("192.0.2.1"))).isEqualTo(INVALID_PROOF);
		}
		var mapped = java.net.Inet6Address.getByAddress(null, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 255, (byte) 255, (byte) 192, 0, 2, 1 }, -1);
		assertThat(this.completions.complete(UUID.randomUUID().toString(), "invalid", PASSWORD,
				new PasswordRecoveryContext("browser:password-recovery", mapped, UUID.randomUUID()))).isEqualTo(THROTTLED);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(30);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery_limit WHERE dimension = 'source'").query(Long.class).single()).isEqualTo(1);
		assertThat(count("password_recovery_throttled")).isEqualTo(1);
	}

	@Test
	void malformedIdentifiersUseOneBoundedAccountBucketAndDtoTextHidesSecrets() {
		for (String id : List.of("invalid", "1-1-1-1-1", "", "another")) {
			assertThat(this.completions.complete(id, "invalid", PASSWORD, context("192.0.2.1"))).isEqualTo(INVALID_PROOF);
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(1);
		assertThat(new IdentityPasswordRecoveryCompletionRequest("private-id", "private-proof", "private-password").toString()).doesNotContain("private-id", "private-proof", "private-password");
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
			assertThat(count("password_recovery_completed")).isEqualTo(1);
			assertThat(count("password_recovery_failed")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "reissue", "cancel", "disable", "version" })
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
					case "reissue" -> this.jdbc.sql("UPDATE iam_password_recovery SET token_digest = :digest WHERE user_id = :id").param("digest", this.tokens.digest(this.tokens.generate())).param("id", proof.userId()).update();
					case "cancel" -> this.jdbc.sql("UPDATE iam_password_recovery SET status = 'cancelled', finished_at = clock_timestamp() WHERE user_id = :id").param("id", proof.userId()).update();
					case "disable" -> this.states.disable(proof.userId(), SYSTEM);
					case "version" -> this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id").param("id", proof.userId()).update();
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
			assertThat(this.passwords.matches(OLD_PASSWORD, hash(proof.userId()))).isTrue();
			assertThat(count("password_recovery_completed")).isZero();
			assertThat(count("password_recovery_failed")).isEqualTo(1);
		}
	}

	@Test
	void requiredFailureAuditAndBudgetWritesMustCommitBeforeReturningADenial() {
		var proof = proof("alice");
		for (String table : List.of("iam_security_audit", "iam_password_recovery_limit")) {
			this.jdbc.sql("CREATE FUNCTION recovery_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
			this.jdbc.sql("CREATE TRIGGER recovery_denial_fault BEFORE " + (table.equals("iam_security_audit") ? "INSERT" : "UPDATE") + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION recovery_denial_fault()").update();
			try {
				assertThatThrownBy(() -> this.completions.complete(proof.userId().toString(), "invalid", PASSWORD, context("192.0.2.1"))).isInstanceOf(IllegalStateException.class);
			}
			finally { this.jdbc.sql("DROP FUNCTION recovery_denial_fault() CASCADE").update(); }
			assertThat(count("password_recovery_failed")).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery_limit").query(Long.class).single()).isZero();
			assertOriginalPasswordAndIssuedProof(proof);
		}
	}

	@Test
	void cleanupRemovesOldBudgetRowsWithoutRemovingLiveFailures() {
		this.completions.complete(UUID.randomUUID().toString(), "invalid", PASSWORD, context("192.0.2.1"));
		this.jdbc.sql("UPDATE iam_password_recovery_limit SET window_started_at = clock_timestamp() - INTERVAL '2 days' WHERE dimension = 'account'").update();
		this.completions.cleanUpExpiredLimits();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery_limit WHERE dimension = 'account'").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT failures FROM iam_password_recovery_limit WHERE dimension = 'source'").query(Integer.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@CsvSource({ "password,UPDATE", "proof,UPDATE", "sessions,DELETE", "audit,INSERT", "limits,UPDATE" })
	void storageFailuresRollBackPasswordProofSessionsAndSuccessAudit(String fault, String mutation) throws Exception {
		var proof = proof("alice");
		createSession("alice");
		String table = switch (fault) {
			case "password" -> "iam_password";
			case "proof" -> "iam_password_recovery";
			case "sessions" -> "iam_browser_session";
			case "audit" -> "iam_security_audit";
			case "limits" -> "iam_password_recovery_limit";
			default -> throw new AssertionError(fault);
		};
		this.jdbc.sql("CREATE FUNCTION recovery_completion_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected recovery failure'; END $$").update();
		this.jdbc.sql("CREATE TRIGGER recovery_completion_fault BEFORE " + mutation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION recovery_completion_fault()").update();
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var response = post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf)));
			assertThat(response.statusCode()).isEqualTo(503);
			assertSecurityHeaders(response);
			assertThat(response.body()).doesNotContain(PASSWORD, proof.token());
		}
		finally { this.jdbc.sql("DROP FUNCTION recovery_completion_fault() CASCADE").update(); }
		assertOriginalPasswordAndIssuedProof(proof);
		assertThat(count("password_recovery_completed")).isZero();
		assertThat(targetSessionCount(proof.userId())).isEqualTo(1);
		assertThat(this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1"))).isEqualTo(COMPLETED);
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "proof", "sessions", "audit", "limits" })
	void silentAndDeferredStorageFailuresCannotReportSuccess(String fault) throws Exception {
		var proof = proof("alice");
		createSession("alice");
		String table = fault.equals("password") ? "iam_password" : fault.equals("proof") ? "iam_password_recovery" : fault.equals("sessions") ? "iam_browser_session" : fault.equals("limits") ? "iam_password_recovery_limit" : "iam_security_audit";
		String mutation = fault.equals("audit") ? "INSERT" : fault.equals("sessions") ? "DELETE" : "UPDATE";
		for (boolean deferred : List.of(false, true)) {
			this.jdbc.sql("CREATE FUNCTION recovery_completion_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
					+ (deferred ? "RAISE EXCEPTION 'deferred recovery failure';" : "RETURN NULL;") + " END $$").update();
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER recovery_completion_fault AFTER " : "CREATE TRIGGER recovery_completion_fault BEFORE ")
					+ mutation + " ON " + table + (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION recovery_completion_fault()").update();
			try (var client = client()) {
				var csrf = get(client, "/api/csrf", null);
				assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(503);
			}
			finally { this.jdbc.sql("DROP FUNCTION recovery_completion_fault() CASCADE").update(); }
			assertOriginalPasswordAndIssuedProof(proof);
			assertThat(count("password_recovery_completed")).isZero();
			assertThat(targetSessionCount(proof.userId())).isEqualTo(1);
		}
	}

	@Test
	void sessionPersistenceFailurePreventsAnyCredentialMutation() throws Exception {
		var proof = proof("alice");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			this.jdbc.sql("CREATE FUNCTION recovery_session_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'session failed'; END $$").update();
			this.jdbc.sql("CREATE TRIGGER recovery_session_fault BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION recovery_session_fault()").update();
			try {
				assertThat(post(client, PATH, cookie(csrf), form(proof.userId().toString(), proof.token(), PASSWORD, csrf(csrf))).statusCode()).isEqualTo(503);
			}
			finally { this.jdbc.sql("DROP FUNCTION recovery_session_fault() CASCADE").update(); }
			assertOriginalPasswordAndIssuedProof(proof);
			assertThat(count("password_recovery_completed")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "sessions", "audit", "limits" })
	void expiryDuringWritingRollsBackAllMutationsAndPersistsOnlyTheDenial(String waitingAt) throws Exception {
		var proof = proof("alice");
		createSession("alice");
		this.jdbc.sql("UPDATE iam_password_recovery SET expires_at = clock_timestamp() + INTERVAL '2 seconds' WHERE user_id = :id").param("id", proof.userId()).update();
		try (var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173804)"); }
			String guard = waitingAt.equals("audit") ? "IF NEW.action <> 'password_recovery_completed' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION recovery_completion_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173804); RETURN " + (waitingAt.equals("sessions") ? "OLD" : "NEW") + "; END $$").update();
			this.jdbc.sql("CREATE TRIGGER recovery_completion_wait BEFORE " + (waitingAt.equals("audit") ? "INSERT" : waitingAt.equals("sessions") ? "DELETE" : "UPDATE") + " ON " + (waitingAt.equals("audit") ? "iam_security_audit" : waitingAt.equals("sessions") ? "iam_browser_session" : waitingAt.equals("limits") ? "iam_password_recovery_limit" : "iam_password") + " FOR EACH ROW EXECUTE FUNCTION recovery_completion_wait()").update();
			var waiting = executor.submit(() -> this.completions.complete(proof.userId().toString(), proof.token(), PASSWORD, context("192.0.2.1")));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))").param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT expires_at <= clock_timestamp() FROM iam_password_recovery WHERE user_id = :id").param("id", proof.userId()).query(Boolean.class).single());
				blocker.rollback();
				assertThat(waiting.get(15, TimeUnit.SECONDS)).isEqualTo(INVALID_PROOF);
			}
			finally { blocker.rollback(); this.jdbc.sql("DROP FUNCTION recovery_completion_wait() CASCADE").update(); }
			assertOriginalPasswordAndIssuedProof(proof);
			assertThat(count("password_recovery_completed")).isZero();
			assertThat(count("browser_sessions_revoked")).isZero();
			assertThat(count("password_recovery_failed")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT sum(failures) FROM iam_password_recovery_limit").query(Long.class).single()).isEqualTo(2);
		}
	}

	@Test
	void migrationFromV18PreservesPasswordProofBudgetsSessionsAndAudits() throws Exception {
		String schema = "recovery_completion_upgrade";
		Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target("18").load().migrate();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			connection.setSchema(schema);
			var isolated = JdbcClient.create(new SingleConnectionDataSource(connection, true));
			UUID id = UUID.randomUUID();
			isolated.sql("INSERT INTO iam_user(id,username,display_name,status) VALUES (:id,'before','Before','active')").param("id", id).update();
			isolated.sql("INSERT INTO iam_password(user_id,password_hash,credential_version) VALUES (:id,:hash,7)").param("id", id).param("hash", this.passwords.hash(OLD_PASSWORD, "before")).update();
			isolated.sql("INSERT INTO iam_password_recovery(user_id,token_digest,credential_version,status,issued_at,expires_at) VALUES (:id,repeat('b',64),7,'issued',clock_timestamp(),clock_timestamp()+INTERVAL '30 minutes')").param("id", id).update();
			isolated.sql("INSERT INTO iam_account_setup_limit(dimension,subject_key,failures) VALUES ('account',repeat('a',64),3)").update();
			isolated.sql("INSERT INTO iam_security_audit(id,action,target_user_id,actor,source,outcome,correlation_id) VALUES (:event,'password_recovery_issued',:id,'system:upgrade','internal:test','success',:correlation)")
					.param("event", UUID.randomUUID()).param("id", id).param("correlation", UUID.randomUUID()).update();
			UUID session = UUID.randomUUID();
			isolated.sql("INSERT INTO iam_browser_session(primary_id,session_id,creation_time,last_access_time,max_inactive_interval,expiry_time,principal_name) VALUES (:id,:session,1,1,1800,1800001,:user)")
					.param("id", session.toString()).param("session", UUID.randomUUID().toString()).param("user", id.toString()).update();
			isolated.sql("INSERT INTO iam_browser_session_attributes(session_primary_id,attribute_name,attribute_bytes) VALUES (:id,'before',:bytes)")
					.param("id", session.toString()).param("bytes", new byte[] {1,2,3}).update();
			var tables = List.of("iam_user", "iam_password", "iam_password_recovery", "iam_account_setup_limit", "iam_browser_session", "iam_browser_session_attributes", "iam_security_audit");
			var before = new java.util.LinkedHashMap<String, List<String>>();
			for (String table : tables) { before.put(table, isolated.sql("SELECT to_jsonb(t)::text FROM " + table + " t").query(String.class).list()); }
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).load().migrate();
			for (String table : tables) { assertThat(isolated.sql("SELECT to_jsonb(t)::text FROM " + table + " t").query(String.class).list()).as(table).isEqualTo(before.get(table)); }
			assertThat(isolated.sql("SELECT count(*) FROM iam_password_recovery_limit").query(Long.class).single()).isZero();
			isolated.sql("INSERT INTO iam_security_audit(id,action,actor,source,outcome,correlation_id) VALUES (:event,'password_recovery_throttled','anonymous','browser:password-recovery','failure',:correlation)")
					.param("event", UUID.randomUUID()).param("correlation", UUID.randomUUID()).update();
		}
		finally { this.jdbc.sql("DROP SCHEMA recovery_completion_upgrade CASCADE").update(); }
	}

	private IdentityPasswordRecovery proof(String username) {
		var user = this.users.create(username, "Private Name", SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), setup.token(), OLD_PASSWORD, "internal:test", UUID.randomUUID());
		return this.recoveries.issue(user.id(), SYSTEM);
	}

	private String createSession(String username) throws Exception {
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			var login = post(client, "/login", cookie(csrf), credentials(username, OLD_PASSWORD, csrf(csrf)));
			assertThat(login.statusCode()).isEqualTo(204);
			return cookie(login);
		}
	}

	private static String form(String userId, String token, String password, String csrf) {
		return "userId=" + encode(userId) + "&token=" + encode(token) + "&newPassword=" + encode(password) + "&_csrf=" + encode(csrf);
	}
	private URI uri() { return URI.create("https://localhost:" + this.port + PATH); }
	private long targetSessionCount(UUID id) { return this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", id.toString()).query(Long.class).single(); }
	private String hash(UUID id) { return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", id).query(String.class).single(); }
	private String proofStatus(UUID id) { return this.jdbc.sql("SELECT status FROM iam_password_recovery WHERE user_id = :id").param("id", id).query(String.class).single(); }
	private long count(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action AND source = 'browser:password-recovery'").param("action", action).query(Long.class).single(); }
	private void assertOriginalPasswordAndIssuedProof(IdentityPasswordRecovery proof) {
		assertThat(this.users.findById(proof.userId()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
		assertThat(this.passwords.matches(OLD_PASSWORD, hash(proof.userId()))).isTrue();
		assertThat(proofStatus(proof.userId())).isEqualTo("issued");
		assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", proof.userId()).query(Long.class).single()).isEqualTo(1);
	}
	private void expire(UUID id) { this.jdbc.sql("UPDATE iam_password_recovery SET issued_at=clock_timestamp()-INTERVAL '31 minutes', expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE user_id=:id").param("id", id).update(); }
	private static PasswordRecoveryContext context(String address) {
		try { return new PasswordRecoveryContext("browser:password-recovery", InetAddress.getByName(address), UUID.randomUUID()); }
		catch (java.net.UnknownHostException ex) { throw new IllegalArgumentException(ex); }
	}

}
