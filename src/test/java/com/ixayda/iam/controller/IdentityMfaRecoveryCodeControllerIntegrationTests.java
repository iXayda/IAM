package com.ixayda.iam.controller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.dto.IdentityMfaRecoveryCodeIssueRequest;
import com.ixayda.iam.dto.IdentityMfaRecoveryCodesResponse;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityMfaRecoveryCodes;
import com.ixayda.iam.service.IdentityTotps;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import com.jayway.jsonpath.JsonPath;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.SerializationUtils;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "iam.browser.requests-per-second=1000")
@Import({ PostgreSqlTestConfiguration.class, IdentityMfaRecoveryCodeControllerIntegrationTests.ConcurrentRequests.class })
class IdentityMfaRecoveryCodeControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/me/mfa/recovery-codes";
	private static final String SOURCE = "browser:mfa-recovery-codes";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:recovery-code-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private RequestPause pause;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@Test
	void aPasswordSessionCanRegenerateOnlyItsOwnCodesWithoutGainingManagementPermission() throws Exception {
		var factor = factor("alice");
		var other = factor("bobby");
		var untouched = this.recoveryCodes.issue(other.userId(), code(other), context()).orElseThrow();
		try (var client = client()) {
			String session = login(client, "alice");
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			var response = regenerate(client, session, code(factor));
			assertThat(response.statusCode()).isEqualTo(200);
			assertSecurityHeaders(response);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			Map<String, Object> result = JsonPath.read(response.body(), "$");
			assertThat(result).containsOnlyKeys("generationId", "codes", "issuedAt");
			List<String> codes = JsonPath.read(response.body(), "$.codes");
			assertThat(codes).hasSize(10).doesNotHaveDuplicates().allMatch(value -> value.matches("[0-9a-f]{4}(-[0-9a-f]{4}){7}"));
			UUID generation = UUID.fromString(JsonPath.read(response.body(), "$.generationId"));
			assertThat(Instant.parse(JsonPath.read(response.body(), "$.issuedAt"))).isBeforeOrEqualTo(Instant.now());
			assertThat(generation(factor)).isEqualTo(generation);
			assertThat(generation(other)).isEqualTo(untouched.generationId());
			String storage = this.jdbc.sql("SELECT string_agg(code_digest, ',') FROM iam_mfa_recovery_code").query(String.class).single();
			for (String secret : codes) { assertThat(storage).doesNotContain(secret); }
			assertThat(this.recoveryCodes.consume(factor.userId(), codes.getFirst(), recoveryContext())).isPresent();
			assertThat(this.recoveryCodes.consume(factor.userId(), codes.getFirst(), recoveryContext())).isEmpty();
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			assertThat(response.body()).doesNotContain(PASSWORD, factor.secret(), "factorId", "userId", "credentialVersion", "token");
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE source = :source").param("source", SOURCE).query(String.class).list())
					.hasSize(2).containsOnly("user:" + factor.userId());
			assertThat(this.jdbc.sql("SELECT count(DISTINCT correlation_id) FROM iam_security_audit WHERE source = :source").param("source", SOURCE).query(Long.class).single()).isEqualTo(1);
			String audit = this.jdbc.sql("SELECT string_agg(actor || source || action, ',') FROM iam_security_audit").query(String.class).single();
			for (String secret : codes) { assertThat(audit).doesNotContain(secret); }
		}
	}

	@Test
	void replacingTheSetInvalidatesEveryOldCodeAndTheOperationCodeCannotBeReplayed() throws Exception {
		var factor = factor("alice");
		var old = this.recoveryCodes.issue(factor.userId(), code(factor), context()).orElseThrow();
		try (var client = client()) {
			String session = login(client, "alice");
			String fresh = futureCode(factor);
			var response = regenerate(client, session, fresh);
			assertThat(response.statusCode()).isEqualTo(200);
			UUID replacement = generation(factor);
			assertThat(replacement).isNotEqualTo(old.generationId());
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_code WHERE generation_id = :id").param("id", old.generationId()).query(Long.class).single()).isZero();
			assertThat(this.recoveryCodes.consume(factor.userId(), old.codes().getFirst(), recoveryContext())).isEmpty();
			assertRejected(regenerate(client, session, fresh), 400);
			assertThat(generation(factor)).isEqualTo(replacement);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
		}
	}

	@Test
	void aNewTotpIsRequiredEvenWhenTheAdministratorSessionAlreadyHasMfa() throws Exception {
		var factor = factor("alice");
		// Seed the administrator so MFA and regeneration each verify their own fresh factor step.
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			this.jdbc.sql("UPDATE iam_admin_bootstrap SET initial_user_id = :id, completed_at = clock_timestamp(), revision = 1").param("id", factor.userId()).update();
			this.jdbc.sql("INSERT INTO iam_administrator(user_id) VALUES (:id)").param("id", factor.userId()).update();
		});
		try (var client = client()) {
			String session = login(client, "alice");
			String code = code(factor);
			var mfa = post(client, "/admin/mfa", session, form(code, csrf(get(client, "/api/csrf", session))));
			assertThat(mfa.statusCode()).isEqualTo(204);
			session = cookie(mfa);
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			Object evidence = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			assertRejected(regenerate(client, session, code), 400);
			assertThat(regenerate(client, session, futureCode(factor)).statusCode()).isEqualTo(200);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isEqualTo(evidence);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "1", "12345", "1234567", "abcdef", "１２３４５６", "123%20456", "%20123456", "123456%0A" })
	void missingAndMalformedCodesUseTheSharedFailureBudget(String code) throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var response = post(client, PATH, session, "code=" + code + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
			assertRejected(response, 400);
			assertThat(failures()).isEqualTo(1);
			assertThat(events("totp_auth_failed")).isEqualTo(1);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@Test
	void omittedCodeCannotBeSuppliedThroughARequestHeader() throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("code", code(factor)).header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
					.POST(HttpRequest.BodyPublishers.noBody()).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 400);
			assertThat(failures()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "code=123456", "userId=00000000-0000-0000-0000-000000000001", "factorId=00000000-0000-0000-0000-000000000001", "source=forged", "actor=forged", "_csrf=extra", "codes=forged" })
	void duplicateAndExtraFieldsCannotChangeTheCallerOrRecoverySet(String extra) throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var response = post(client, PATH, session, form(code(factor), csrf(get(client, "/api/csrf", session))) + "&" + extra);
			assertThat(response.statusCode()).isEqualTo(400);
			assertThat(response.body()).contains("BAD_REQUEST");
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			assertThat(failures()).isZero();
		}
	}

	@Test
	void queryParametersJsonMissingCsrfAndUnacceptableResponsesAreRejectedBeforeConsumption() throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			String code = code(factor);
			assertThat(post(client, PATH + "?code=" + code, session, form(code, token)).statusCode()).isEqualTo(400);
			var json = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/json")
					.header("X-CSRF-TOKEN", token).POST(HttpRequest.BodyPublishers.ofString("{\"code\":\"" + code + "\"}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			assertThat(post(client, PATH, session, "code=" + code).statusCode()).isEqualTo(403);
			var unacceptable = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("Accept", "text/html").POST(HttpRequest.BodyPublishers.ofString(form(code, token))).build();
			assertThat(client.send(unacceptable, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(406);
			assertThat(events("totp_authenticated")).isZero();
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			assertThat(failures()).isZero();
		}
	}

	@Test
	void csrfHeaderIsSupportedAndSecretHeadersDoNotOverrideTheBody() throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session))).header("code", "bad")
					.POST(HttpRequest.BodyPublishers.ofString("code=" + code(factor))).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void anonymousRequestsAreDeniedAndAnAccountWithoutAnActiveFactorCannotGenerateCodes() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var anonymous = get(client, "/api/csrf", null);
			assertThat(post(client, PATH, cookie(anonymous), form("123456", csrf(anonymous))).statusCode()).isEqualTo(401);
			String session = login(client, "alice");
			assertRejected(regenerate(client, session, "123456"), 400);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" })
	void onlyPostIsExposedAndRecoverySecretsCannotBeReadBack(String method) throws Exception {
		factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session)
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
					.method(method, HttpRequest.BodyPublishers.noBody()).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
		}
	}

	@Test
	void totpFailuresAreSharedWithOtherEntriesAndEvenACorrectCodeIsThrottled() throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			for (int i = 0; i < 4; i++) { assertThat(this.totps.verify(factor.userId(), "bad", context())).isEmpty(); }
			assertRejected(regenerate(client, session, "bad"), 400);
			assertThat(failures()).isEqualTo(5);
			assertRejected(regenerate(client, session, code(factor)), 429);
			assertThat(events("totp_auth_throttled")).isEqualTo(1);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@Test
	void sourceThrottlingIsSharedAcrossUsersAndCannotBeBypassedWithForwardedHeaders() throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String body = form(code(factor), csrf(get(client, "/api/csrf", session)));
			for (int i = 0; i < 30; i++) { assertThat(this.totps.verify(UUID.randomUUID(), "bad", context())).isEmpty(); }
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Forwarded-For", "192.0.2.88").header("Forwarded", "for=192.0.2.88")
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 429);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@Test
	void anUnchangedSessionIsNotSavedAgainAfterTheIssuanceTransaction() throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String body = form(code(factor), csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("CREATE SEQUENCE regeneration_session_saves").update();
			this.jdbc.sql("CREATE FUNCTION regeneration_second_save() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('regeneration_session_saves') > 1 THEN RAISE EXCEPTION 'unexpected repeated session write'; END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER regeneration_second_save BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION regeneration_second_save()").update();
			try {
				assertThat(post(client, PATH, session, body).statusCode()).isEqualTo(200);
				assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
				assertThat(this.jdbc.sql("SELECT last_value FROM regeneration_session_saves").query(Long.class).single()).isEqualTo(1);
				assertUnavailable(get(client, "/api/me", session));
				assertThat(this.jdbc.sql("SELECT last_value FROM regeneration_session_saves").query(Long.class).single()).isEqualTo(2);
			}
			finally {
				this.jdbc.sql("DROP FUNCTION regeneration_second_save() CASCADE").update();
				this.jdbc.sql("DROP SEQUENCE regeneration_session_saves").update();
			}
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@CsvSource({ "version, 401", "disabled, 401", "password-expiry, 401", "session, 401", "factor, 400" })
	void stateChangesAfterHttpAuthenticationAreRecheckedInsideTheWorkflow(String operation, int expected) throws Exception {
		var factor = factor("alice");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String body = form(code(factor), csrf(get(client, "/api/csrf", session)));
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Test-Pause", "true").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (operation.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
				else if (operation.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled'").update(); }
				else if (operation.equals("password-expiry")) { this.pause.expirePassword = true; }
				else if (operation.equals("factor")) { this.jdbc.sql("DELETE FROM iam_user_totp").update(); }
				else { this.jdbc.sql("DELETE FROM iam_browser_session").update(); }
			}
			finally { this.pause.release.countDown(); }
			var response = waiting.get(15, TimeUnit.SECONDS);
			assertThat(response.statusCode()).isEqualTo(expected);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@Test
	void concurrentRequestsCannotRegenerateTwoSetsWithTheSameCode() throws Exception {
		var factor = factor("alice");
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = login(client, "alice");
			String body = form(code(factor), csrf(get(client, "/api/csrf", session)));
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return post(client, PATH, session, body); });
			var second = executor.submit(() -> { start.await(); return post(client, PATH, session, body); });
			start.countDown();
			assertThat(List.of(first.get(20, TimeUnit.SECONDS).statusCode(), second.get(20, TimeUnit.SECONDS).statusCode())).containsExactlyInAnyOrder(200, 400);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "user", "session" })
	void idleExpirationIsRecheckedAfterWaitingForTheUserOrSessionLock(String locked) throws Exception {
		var factor = factor("alice");
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String body = form(futureCode(factor), csrf(get(client, "/api/csrf", session)));
			long before = lastStep(factor);
			long deadline = System.currentTimeMillis() + 2000;
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :deadline").param("deadline", deadline).update();
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.prepareStatement(locked.equals("user") ? "SELECT id FROM iam_user WHERE id = ? FOR UPDATE" : "SELECT session_id FROM iam_browser_session WHERE session_id = ? FOR UPDATE")) {
				statement.setObject(1, locked.equals("user") ? factor.userId() : session.substring(session.indexOf('=') + 1)); statement.executeQuery().close();
			}
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Test-Pause", "true").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(5, TimeUnit.SECONDS)).isTrue();
				this.pause.release.countDown();
				awaitBlocked(pid);
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(401);
			}
			finally { this.pause.release.countDown(); blocker.rollback(); }
			assertThat(lastStep(factor)).isEqualTo(before);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "codes,absolute", "audit,absolute", "session,absolute", "codes,idle", "audit,idle", "session,idle" })
	void expiryDuringIssuanceRollsBackTheSetCodeAndSuccessEvents(String waitingAt, String deadlineType) throws Exception {
		var factor = factor("alice");
		var old = this.recoveryCodes.issue(factor.userId(), code(factor), context()).orElseThrow();
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String body = form(futureCode(factor), csrf(get(client, "/api/csrf", session)));
			long before = lastStep(factor);
			long deadline = System.currentTimeMillis() + 2500;
			if (deadlineType.equals("idle")) {
				this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
						.param("expiry", deadline).param("id", session.substring(session.indexOf('=') + 1)).update();
			}
			else { replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, deadline - 28_800_000); }
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173842)"); }
			String guard = waitingAt.equals("audit") ? "IF NEW.action <> 'mfa_recovery_codes_generated' OR NEW.source <> '" + SOURCE + "' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION regeneration_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173842); RETURN NEW; END $$").update();
			String table = waitingAt.equals("codes") ? "iam_mfa_recovery_code" : waitingAt.equals("audit") ? "iam_security_audit" : "iam_browser_session";
			this.jdbc.sql("CREATE TRIGGER regeneration_wait BEFORE " + (waitingAt.equals("session") ? "UPDATE" : "INSERT") + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION regeneration_wait()").update();
			var waiting = executor.submit(() -> post(client, PATH, session, body));
			try {
				awaitBlocked(pid);
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertUnavailable(waiting.get(15, TimeUnit.SECONDS));
			}
			finally { blocker.rollback(); this.jdbc.sql("DROP FUNCTION regeneration_wait() CASCADE").update(); }
			assertThat(generation(factor)).isEqualTo(old.generationId());
			assertThat(lastStep(factor)).isEqualTo(before);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			assertThat(events("totp_authenticated")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "codes, error", "codes, silent", "codes, deferred", "delete, error", "delete, silent", "delete, deferred",
			"audit, error", "audit, silent", "audit, deferred", "factor-audit, error", "factor-audit, silent", "factor-audit, deferred",
			"session, error", "session, silent", "session, deferred" })
	void storageAuditAndSessionFailuresPreserveTheOldSetAndDoNotConsumeTheCode(String target, String mode) throws Exception {
		var factor = factor("alice");
		var old = this.recoveryCodes.issue(factor.userId(), code(factor), context()).orElseThrow();
		try (var client = client()) {
			String session = login(client, "alice");
			String body = form(futureCode(factor), csrf(get(client, "/api/csrf", session)));
			long before = lastStep(factor);
			String table = target.equals("codes") || target.equals("delete") ? "iam_mfa_recovery_code" : target.equals("session") ? "iam_browser_session" : "iam_security_audit";
			String guard = target.contains("audit") ? "IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + (target.equals("factor-audit") ? "totp_authenticated" : "mfa_recovery_codes_generated") + "' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION regeneration_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected regeneration failure';") + " END $$").update();
			String operation = target.equals("delete") ? "DELETE" : target.equals("session") ? "UPDATE" : "INSERT";
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER regeneration_fault AFTER " : "CREATE TRIGGER regeneration_fault BEFORE ")
					+ operation + " ON " + table + (mode.equals("deferred") ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION regeneration_fault()").update();
			try { assertUnavailable(post(client, PATH, session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION regeneration_fault() CASCADE").update(); }
			assertThat(generation(factor)).isEqualTo(old.generationId());
			assertThat(lastStep(factor)).isEqualTo(before);
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			assertThat(events("totp_authenticated")).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent", "deferred" })
	void failureAuditFaultsRollbackTheSharedFailureBudget(String mode) throws Exception {
		var factor = factor("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String body = form("bad", csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("CREATE FUNCTION regeneration_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source = '" + SOURCE + "' AND NEW.action = 'totp_auth_failed' THEN "
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected denial failure';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER regeneration_denial_fault AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER regeneration_denial_fault BEFORE INSERT ON iam_security_audit") + " FOR EACH ROW EXECUTE FUNCTION regeneration_denial_fault()").update();
			try { assertUnavailable(post(client, PATH, session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION regeneration_denial_fault() CASCADE").update(); }
			assertThat(failures()).isZero();
			assertThat(events("totp_auth_failed")).isZero();
		}
	}

	@Test
	void callerTransactionsAreRejectedAndDtoTextRedactsSecrets() {
		var factor = factor("alice");
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.recoveryCodes.issueForSession(factor.userId(), "untrusted-session", 1, System.currentTimeMillis(), "123456", context(), () -> {})))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("independent transaction");
		assertThat(new IdentityMfaRecoveryCodeIssueRequest("123456").toString()).doesNotContain("123456");
		var codes = new java.util.ArrayList<>(List.of("sensitive-code"));
		var response = new IdentityMfaRecoveryCodesResponse(UUID.randomUUID(), codes, Instant.now());
		codes.clear();
		assertThat(response.codes()).containsExactly("sensitive-code");
		assertThat(response.toString()).doesNotContain("sensitive-code");
		assertThatThrownBy(() -> response.codes().clear()).isInstanceOf(UnsupportedOperationException.class);
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean RequestPause recoveryCodePause() { return new RequestPause(); }
		@Bean WebMvcConfigurer recoveryCodePauseConfiguration(RequestPause pause) {
			return new WebMvcConfigurer() {
				@Override public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class RequestPause implements HandlerInterceptor {
		private volatile CountDownLatch entered;
		private volatile CountDownLatch release;
		private volatile boolean expirePassword;
		void start() {
			this.entered = new CountDownLatch(1); this.release = new CountDownLatch(1); this.expirePassword = false;
		}
		@Override public boolean preHandle(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, Object handler) throws Exception {
			if ("true".equals(request.getHeader("X-Test-Pause"))) {
				this.entered.countDown();
				assertThat(this.release.await(10, TimeUnit.SECONDS)).isTrue();
				if (this.expirePassword) { request.getSession(false).setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, System.currentTimeMillis() - 28_800_001); }
			}
			return true;
		}
	}

	private UUID activeUser(String username) {
		var user = this.users.create(username, username, SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return user.id();
	}
	private IdentityTotpEnrollment factor(String username) {
		UUID userId = activeUser(username);
		for (int attempt = 0; attempt < 10; attempt++) {
			var factor = this.totps.beginEnrollment(userId, SYSTEM);
			long step = step();
			if (Stream.of(step - 1, step, step + 1, step + 2).map(value -> otp(factor, value)).distinct().count() == 4) {
				// Enrollment confirmation has separate coverage; issuance needs an unused current step.
				this.jdbc.sql("UPDATE iam_user_totp SET status = 'active', activated_at = issued_at, last_used_step = :step WHERE user_id = :id")
						.param("id", userId).param("step", step - 1).update();
				return factor;
			}
		}
		throw new AssertionError("Cannot create distinct adjacent TOTP codes for the fixture");
	}
	private String login(HttpClient client, String username) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(username, PASSWORD, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}
	private HttpResponse<String> regenerate(HttpClient client, String session, String code) throws Exception {
		return post(client, PATH, session, form(code, csrf(get(client, "/api/csrf", session))));
	}
	private static String form(String code, String token) { return "code=" + encode(code) + "&_csrf=" + encode(token); }
	private String base() { return "https://localhost:" + this.port + PATH; }
	private long failures() { return this.jdbc.sql("SELECT COALESCE(sum(failures), 0) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single(); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action AND source = :source").param("action", action).param("source", SOURCE).query(Long.class).single(); }
	private UUID generation(IdentityTotpEnrollment factor) { return this.jdbc.sql("SELECT DISTINCT generation_id FROM iam_mfa_recovery_code WHERE user_id = :id").param("id", factor.userId()).query(UUID.class).single(); }
	private long lastStep(IdentityTotpEnrollment factor) { return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id = :id").param("id", factor.userId()).query(Long.class).single(); }
	private Object attribute(String cookie, String name) {
		byte[] value = this.jdbc.sql("SELECT a.attribute_bytes FROM iam_browser_session_attributes a JOIN iam_browser_session s ON s.primary_id = a.session_primary_id WHERE s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).query(byte[].class).single();
		return SerializationUtils.deserialize(value);
	}
	private void replaceAttribute(String cookie, String name, Object value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update();
	}
	private void awaitBlocked(int pid) {
		await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
				.param("pid", pid).query(Boolean.class).single());
	}
	private static void assertRejected(HttpResponse<String> response, int status) {
		assertThat(response.statusCode()).isEqualTo(status);
		assertSecurityHeaders(response);
		assertThat(response.body()).isEqualTo(status == 429 ? "Verification temporarily unavailable" : "Recovery code regeneration rejected");
	}
	private static void assertUnavailable(HttpResponse<String> response) {
		assertThat(response.statusCode()).isEqualTo(503);
		assertSecurityHeaders(response);
		assertThat(response.body()).contains("SERVICE_UNAVAILABLE").doesNotContain("codes", "injected", "SQL", "connection", PASSWORD);
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
	}
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static MfaRecoveryCodeContext recoveryContext() { return new MfaRecoveryCodeContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-recovery-code-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static long step() { return Math.floorDiv(Instant.now().getEpochSecond(), 30); }
	private static String code(IdentityTotpEnrollment factor) { return otp(factor, step()); }
	private static String futureCode(IdentityTotpEnrollment factor) { return otp(factor, step() + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) {
		byte[] counter = new byte[8]; for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(factor.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(java.util.Locale.ROOT, "%06d", number % 1_000_000);
	}

}
