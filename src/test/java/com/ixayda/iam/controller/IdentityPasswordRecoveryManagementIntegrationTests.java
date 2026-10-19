package com.ixayda.iam.controller;

import java.net.InetAddress;
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
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.dto.IdentityPasswordRecoveryManagementRequest;
import com.ixayda.iam.dto.IdentityPasswordRecoveryResponse;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityTotps;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityPasswordRecoveries;
import com.ixayda.iam.service.IdentityPasswordRecoveryManagement;
import com.ixayda.iam.service.IdentityUserStateChanges;
import com.ixayda.iam.service.IdentityUserStates;
import com.ixayda.iam.service.IdentityUsers;

import tools.jackson.databind.json.JsonMapper;

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
@Import({ PostgreSqlTestConfiguration.class, IdentityPasswordRecoveryManagementIntegrationTests.ConcurrentRequests.class })
class IdentityPasswordRecoveryManagementIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String RECOVERED_PASSWORD = "Nine indigo sailboats beyond the harbor";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:password-recovery-management-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityPasswordRecoveries recoveries;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityPasswordRecoveryManagement management;
	@Autowired private IdentityUserStateChanges stateChanges;
	@Autowired private IdentityUserStates states;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private RequestPause pause;
	@Autowired private PostgreSQLContainer postgres;

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
	void issueReturnsOneCommittedVersionBoundSecretWithoutChangingCredentialsSessionsOrAuthentication() throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			String targetSession = login(client, "bobby");
			String session = elevate(client, login(client, "alice"), factor);
			Object evidence = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			var response = manage(client, session, target.id(), "issue", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(200);
			assertSecurityHeaders(response);
			assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			var delivered = new JsonMapper().readTree(response.body());
			assertThat(delivered.propertyNames()).containsExactlyInAnyOrder("userId", "token", "expiresAt");
			assertThat(delivered.path("userId").asText()).isEqualTo(target.id().toString());
			String token = delivered.path("token").asText();
			assertThat(token).matches("[A-Za-z0-9_-]{43}");
			var stored = this.jdbc.sql("SELECT * FROM iam_password_recovery WHERE user_id = :id").param("id", target.id()).query().singleRow();
			assertThat(stored.get("token_digest")).isNotEqualTo(token);
			assertThat(stored.get("status")).isEqualTo("issued");
			Instant issuedAt = ((java.sql.Timestamp) stored.get("issued_at")).toInstant();
			Instant expiresAt = ((java.sql.Timestamp) stored.get("expires_at")).toInstant();
			assertThat(expiresAt).isEqualTo(issuedAt.plusSeconds(1800));
			assertThat(Instant.parse(delivered.path("expiresAt").asText())).isEqualTo(expiresAt);
			assertThat(this.users.findById(target.id())).contains(target);
			assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", target.id()).query(Long.class).single()).isEqualTo(1);
			assertThat(stored.get("credential_version")).isEqualTo(1L);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isEqualTo(evidence);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			var audit = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = 'password_recovery_issued' AND target_user_id = :id AND source = 'browser:admin-password-recovery-issue'").param("id", target.id()).query().singleRow();
			assertThat(audit).containsEntry("actor", "user:" + factor.userId());
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE correlation_id = :id AND action IN ('password_recovery_issued', 'totp_authenticated')").param("id", audit.get("correlation_id")).query(Long.class).single()).isEqualTo(2);
			assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list()).noneMatch(text -> text.contains(token));
			assertThat(this.jdbc.sql("SELECT attribute_bytes FROM iam_browser_session_attributes").query(byte[].class).list()).noneMatch(bytes -> new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1).contains(token));
			assertThat(get(client, path(target.id(), "issue"), session).statusCode()).isEqualTo(403);
			assertThat(get(client, "/api/me", targetSession).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/me", login(client, "bobby")).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void reissueInvalidatesTheOldProofAndDoesNotExposeItInQueries() throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		var old = this.recoveries.issue(target.id(), SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var response = manage(client, session, target.id(), "issue", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(200);
			String replacement = new JsonMapper().readTree(response.body()).path("token").asText();
			assertThat(replacement).isNotEqualTo(old.token());
			assertThat(this.recoveries.complete(target.id(), old.token(), RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
			assertThat(get(client, "/api/admin/users/" + target.id(), session).body()).doesNotContain(replacement, old.token(), "token");
			assertThat(this.recoveries.complete(target.id(), replacement, RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
			assertThat(events("password_recovery_issued")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "active", "expired", "disabled", "version" })
	void cancelRevokesOutstandingProofWithoutChangingTheAccount(String state) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		var proof = this.recoveries.issue(target.id(), SYSTEM);
		if (state.equals("expired")) {
			this.jdbc.sql("UPDATE iam_password_recovery SET issued_at = clock_timestamp() - INTERVAL '31 minutes', expires_at = clock_timestamp() - INTERVAL '1 minute' WHERE user_id = :id").param("id", target.id()).update();
		}
		if (state.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id").param("id", target.id()).update(); }
		if (state.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", target.id()).update(); }
		var before = this.users.findById(target.id()).orElseThrow();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var response = manage(client, session, target.id(), "cancel", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.body()).isEmpty();
			assertSecurityHeaders(response);
			assertThat(this.jdbc.sql("SELECT status FROM iam_password_recovery WHERE user_id = :id").param("id", target.id()).query(String.class).single()).isEqualTo("cancelled");
			assertThat(this.users.findById(target.id())).contains(before);
			assertThat(events("password_recovery_cancelled")).isEqualTo(1);
			assertThat(this.recoveries.complete(target.id(), proof.token(), RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "absent", "cancelled", "consumed" })
	void cancellationIsIdempotentButStillConsumesFreshTotp(String state) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		if (state.equals("consumed")) {
			var proof = this.recoveries.issue(target.id(), SYSTEM);
			assertThat(this.recoveries.complete(target.id(), proof.token(), RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
		}
		if (state.equals("cancelled")) { this.recoveries.issue(target.id(), SYSTEM); this.recoveries.cancel(target.id(), SYSTEM); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			assertThat(manage(client, session, target.id(), "cancel", code).statusCode()).isEqualTo(204);
			assertThat(manage(client, session, target.id(), "cancel", code).statusCode()).isEqualTo(400);
			assertThat(events("password_recovery_cancelled")).isZero();
			assertThat(this.users.findById(target.id())).contains(target);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "pending", "disabled", "passwordless" })
	void issuanceRefusesIneligibleAccountsWithoutResettingPasswordsOrStatus(String state) throws Exception {
		var factor = administrator();
		var target = state.equals("disabled") ? activeUser("bobby") : this.users.create("bobby", "Private Name", SYSTEM);
		if (state.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", target.id()).update(); }
		if (state.equals("passwordless")) { this.jdbc.sql("UPDATE iam_user SET status = 'active' WHERE id = :id").param("id", target.id()).update(); }
		var before = this.users.findById(target.id()).orElseThrow();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			assertThat(manage(client, session, target.id(), "issue", code).statusCode()).isEqualTo(409);
			assertThat(manage(client, session, target.id(), "issue", code).statusCode()).isEqualTo(400);
			assertThat(events("password_recovery_issued")).isZero();
			assertThat(this.users.findById(target.id())).contains(before);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void unknownTargetsAreOnlyDisclosedAfterFreshTotpVerification(String operation) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			UUID target = UUID.randomUUID();
			assertThat(manage(client, session, target, operation, "invalid").statusCode()).isEqualTo(400);
			String code = freshCode(factor);
			assertThat(manage(client, session, target, operation, code).statusCode()).isEqualTo(404);
			assertThat(manage(client, session, target, operation, code).statusCode()).isEqualTo(400);
			assertThat(events("password_recovery_issued") + events("password_recovery_cancelled")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void anonymousOrdinaryAndPasswordOnlyAdministratorRequestsAreDenied(String operation) throws Exception {
		var factor = administrator();
		activeUser("charlie");
		var target = activeUser("bobby");
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			assertThat(post(client, path(target.id(), operation), cookie(csrf), form(freshCode(factor), csrf(csrf))).statusCode()).isEqualTo(401);
			assertThat(manage(client, login(client, "charlie"), target.id(), operation, freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(manage(client, login(client, "alice"), target.id(), operation, freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(events("password_recovery_issued") + events("password_recovery_cancelled")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void wrongCodesShareTheExistingTotpBudget(String operation) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertThat(manage(client, session, target.id(), operation, otp(factor, lastStep(factor))).statusCode()).isEqualTo(400);
			for (int i = 0; i < 4; i++) { assertThat(manage(client, session, target.id(), operation, "invalid").statusCode()).isEqualTo(400); }
			assertThat(manage(client, session, target.id(), operation, freshCode(factor)).statusCode()).isEqualTo(429);
			assertThat(this.totps.verify(factor.userId(), freshCode(factor), context())).isEmpty();
			assertThat(events("password_recovery_issued") + events("password_recovery_cancelled")).isZero();
		}
	}

	@Test
	void oneCodeCannotConcurrentlyIssueProofsForDifferentTargets() throws Exception {
		var factor = administrator();
		var first = activeUser("bobby");
		var second = activeUser("charlie");
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			var start = new CountDownLatch(1);
			var a = executor.submit(() -> { start.await(); return post(client, path(first.id(), "issue"), session, body); });
			var b = executor.submit(() -> { start.await(); return post(client, path(second.id(), "issue"), session, body); });
			start.countDown();
			assertThat(List.of(a.get(20, TimeUnit.SECONDS).statusCode(), b.get(20, TimeUnit.SECONDS).statusCode())).containsExactlyInAnyOrder(200, 400);
			assertThat(events("password_recovery_issued")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@CsvSource({ "issue,&code=000000", "cancel,&_csrf=duplicate", "issue,&actor=system", "cancel,&status=ACTIVE", "issue,&userId=other", "cancel,&password=forbidden" })
	void duplicateAndUnapprovedParametersCannotChangeTheTargetOrCaller(String operation, String extra) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			var response = post(client, path(target.id(), operation), session, form(freshCode(factor), csrf(get(client, "/api/csrf", session))) + extra);
			assertThat(response.statusCode()).isEqualTo(400);
			assertSecurityHeaders(response);
			assertThat(lastStep(factor)).isEqualTo(step);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void queryParametersWrongMediaMissingCsrfAndUnsupportedMethodsAreRejected(String operation) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			assertThat(post(client, path(target.id(), operation) + "?code=ignored", session, body).statusCode()).isEqualTo(400);
			assertThat(post(client, path(target.id(), operation), session, "code=" + freshCode(factor)).statusCode()).isEqualTo(403);
			var json = HttpRequest.newBuilder(uri(target.id(), operation)).header("Cookie", session).header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			var unsupported = client.send(json, HttpResponse.BodyHandlers.ofString());
			assertThat(unsupported.statusCode()).isEqualTo(415);
			assertErrorResponse(unsupported, "UNSUPPORTED_MEDIA_TYPE");
			for (String method : List.of("GET", "PUT", "PATCH", "DELETE")) {
				var request = HttpRequest.newBuilder(uri(target.id(), operation)).header("Cookie", session).header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
						.method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
			}
			assertThat(post(client, "/api/admin/users/1-1-1-1-1/password-recovery" + (operation.equals("cancel") ? "/cancel" : ""), session, body).statusCode()).isEqualTo(400);
			assertThat(lastStep(factor)).isEqualTo(step);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void csrfHeaderIsAcceptedAndCodeHeadersCannotPopulateTheRequest(String operation) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			var missing = HttpRequest.newBuilder(uri(target.id(), operation)).header("Cookie", session).header("code", freshCode(factor))
					.header("Content-Type", "application/x-www-form-urlencoded").header("X-CSRF-TOKEN", token)
					.POST(HttpRequest.BodyPublishers.noBody()).build();
			assertThat(client.send(missing, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			var correct = HttpRequest.newBuilder(uri(target.id(), operation)).header("Cookie", session)
					.header("Content-Type", "application/x-www-form-urlencoded").header("X-CSRF-TOKEN", token)
					.POST(HttpRequest.BodyPublishers.ofString("code=" + freshCode(factor))).build();
			assertThat(client.send(correct, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(operation.equals("issue") ? 200 : 204);
		}
	}

	@ParameterizedTest
	@CsvSource({ "issue,membership,403", "issue,factor,403", "issue,version,401", "issue,disabled,401", "issue,session,401", "issue,mfa-expiry,403", "issue,password-expiry,401", "cancel,membership,403", "cancel,factor,403", "cancel,version,401", "cancel,disabled,401", "cancel,session,401", "cancel,mfa-expiry,403", "cancel,password-expiry,401" })
	void authorityAndSessionChangesAfterHttpAuthorizationAreRecheckedBeforeMutation(String operation, String fault, int expected) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			this.pause.start();
			var request = HttpRequest.newBuilder(uri(target.id(), operation)).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Test-Pause", "true").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				switch (fault) {
					case "membership" -> this.jdbc.sql("DELETE FROM iam_administrator").update();
					case "factor" -> this.jdbc.sql("DELETE FROM iam_user_totp").update();
					case "version" -> this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id").param("id", factor.userId()).update();
					case "disabled" -> this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", factor.userId()).update();
					case "session" -> this.jdbc.sql("DELETE FROM iam_browser_session").update();
					case "mfa-expiry" -> this.pause.expireEvidence = true;
					case "password-expiry" -> this.pause.expirePassword = true;
					default -> throw new AssertionError(fault);
				}
			}
			finally { this.pause.release.countDown(); }
			var response = waiting.get(15, TimeUnit.SECONDS);
			assertThat(response.statusCode()).isEqualTo(expected);
			assertErrorResponse(response, expected == 401 ? "UNAUTHENTICATED" : "FORBIDDEN");
			assertThat(this.users.findById(target.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(events("password_recovery_issued") + events("password_recovery_cancelled")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "issue,audit", "issue,silent-audit", "issue,deferred-audit", "issue,proof", "issue,silent-proof", "issue,deferred-proof", "issue,session", "issue,silent-session", "issue,deferred-session", "cancel,audit", "cancel,silent-audit", "cancel,deferred-audit", "cancel,proof", "cancel,silent-proof", "cancel,deferred-proof", "cancel,session", "cancel,silent-session", "cancel,deferred-session" })
	void storageAndAuditFailuresRollBackProofCodeSessionAndSuccessEvents(String operation, String fault) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		var previous = this.recoveries.issue(target.id(), SYSTEM);
		String digest = this.jdbc.sql("SELECT token_digest FROM iam_password_recovery WHERE user_id = :id").param("id", target.id()).query(String.class).single();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			long step = lastStep(factor);
			String table = fault.contains("audit") ? "iam_security_audit" : fault.contains("proof") ? "iam_password_recovery" : "iam_browser_session";
			String action = fault.contains("audit") ? "INSERT" : "UPDATE";
			String guard = fault.contains("audit") ? "IF NEW.source <> 'browser:admin-password-recovery-" + operation + "' OR NEW.action <> 'password_recovery_" + (operation.equals("issue") ? "issued" : "cancelled") + "' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION recovery_management_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard
					+ (fault.startsWith("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected recovery management failure';") + " END $$").update();
			this.jdbc.sql((fault.startsWith("deferred") ? "CREATE CONSTRAINT TRIGGER recovery_management_fault AFTER " : "CREATE TRIGGER recovery_management_fault BEFORE ")
					+ action + " ON " + table + (fault.startsWith("deferred") ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION recovery_management_fault()").update();
			try {
				var response = post(client, path(target.id(), operation), session, body);
				assertThat(response.statusCode()).isEqualTo(503);
				assertErrorResponse(response, "SERVICE_UNAVAILABLE");
				assertThat(response.body()).doesNotContain(previous.token(), "expiresAt", "token_digest");
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			}
			finally { this.jdbc.sql("DROP FUNCTION recovery_management_fault() CASCADE").update(); }
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.jdbc.sql("SELECT token_digest FROM iam_password_recovery WHERE user_id = :id AND status = 'issued'").param("id", target.id()).query(String.class).single()).isEqualTo(digest);
			assertThat(this.users.findById(target.id())).contains(target);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE source = :source AND outcome = 'success'").param("source", "browser:admin-password-recovery-" + operation).query(Long.class).single()).isZero();
			assertThat(post(client, path(target.id(), operation), session, body).statusCode()).isEqualTo(operation.equals("issue") ? 200 : 204);
		}
	}

	@ParameterizedTest
	@CsvSource({ "issue,mfa,audit", "issue,password,audit", "cancel,mfa,audit", "cancel,password,audit", "issue,mfa,session", "issue,password,session", "cancel,mfa,session", "cancel,password,session",
			"issue,idle,audit", "cancel,idle,audit", "issue,idle,session", "cancel,idle,session" })
	void expiryDuringSessionOrAuditStorageRollsBackTheProof(String operation, String deadlineType, String waitingAt) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		var previous = this.recoveries.issue(target.id(), SYSTEM);
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			long step = lastStep(factor);
			long deadline = System.currentTimeMillis() + 2500;
			if (deadlineType.equals("mfa")) { setManagementDeadline(session, deadline); }
			else if (deadlineType.equals("idle")) {
				this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
						.param("expiry", deadline).param("id", session.substring(session.indexOf('=') + 1)).update();
			}
			else { setPasswordDeadline(session, deadline); }
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173805)"); }
			String guard = waitingAt.equals("audit") ? "IF NEW.source <> 'browser:admin-password-recovery-" + operation + "' OR NEW.action <> 'password_recovery_" + (operation.equals("issue") ? "issued" : "cancelled") + "' THEN RETURN NEW; END IF; "
					: "IF NOT EXISTS (SELECT 1 FROM iam_security_audit WHERE action = 'totp_authenticated' AND source = 'browser:admin-password-recovery-" + operation + "') THEN RETURN NEW; END IF; ";
			this.jdbc.sql("CREATE FUNCTION recovery_management_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173805); RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER recovery_management_wait BEFORE " + (waitingAt.equals("audit") ? "INSERT ON iam_security_audit" : "UPDATE ON iam_browser_session") + " FOR EACH ROW EXECUTE FUNCTION recovery_management_wait()").update();
			var waiting = executor.submit(() -> post(client, path(target.id(), operation), session, body));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))").param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.rollback();
				var response = waiting.get(15, TimeUnit.SECONDS);
				assertThat(response.statusCode()).isEqualTo(503);
				assertErrorResponse(response, "SERVICE_UNAVAILABLE");
			}
			finally { blocker.rollback(); this.jdbc.sql("DROP FUNCTION recovery_management_wait() CASCADE").update(); }
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(events("password_recovery_issued") + events("password_recovery_cancelled")).isZero();
			assertThat(this.users.findById(target.id())).contains(target);
			// Rollback preserves the previous proof, including after an attempted replacement.
			assertThat(this.recoveries.complete(target.id(), previous.token(), RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
		}
	}

	@Test
	void callerTransactionsAreRejectedAndTextRepresentationsHideSecrets() {
		var factor = administrator();
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.management.manage(factor.userId(), "untrusted", 1, System.currentTimeMillis(), null, UUID.randomUUID(), IdentityPasswordRecoveryManagement.Operation.ISSUE,
						"123456", context(), () -> {}))).isInstanceOf(IllegalStateException.class).hasMessageContaining("independent transaction");
		assertThat(new IdentityPasswordRecoveryManagementRequest("123456").toString()).doesNotContain("123456");
		assertThat(new IdentityPasswordRecoveryResponse(UUID.randomUUID(), "secret-proof", Instant.now()).toString()).doesNotContain("secret-proof");
	}

	@ParameterizedTest
	@ValueSource(strings = { "cancel", "disable" })
	void concurrentIssuanceAndLifecycleChangesSerializeAcrossDifferentAdministratorsAndSources(String operation) throws Exception {
		var first = administrator();
		var second = additionalAdministrator();
		var target = activeUser("bobby");
		this.recoveries.issue(target.id(), SYSTEM);
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String firstSession = elevate(client, login(client, "alice"), first);
			String secondSession = elevate(client, login(client, "second"), second);
			var a = evidence(firstSession);
			var b = evidence(secondSession);
			var start = new CountDownLatch(1);
			var issuance = executor.submit(() -> {
				start.await();
				return this.management.manage(first.userId(), a.id(), a.version(), a.authenticatedAt(), a.management(), target.id(), IdentityPasswordRecoveryManagement.Operation.ISSUE,
						freshCode(first), new TotpAuthenticationContext("internal:test", InetAddress.getByName("192.0.2.1"), UUID.randomUUID()), () -> {});
			});
			var mutation = executor.submit(() -> {
				start.await();
				var context = new TotpAuthenticationContext("internal:test", InetAddress.getByName("192.0.2.2"), UUID.randomUUID());
				if (operation.equals("cancel")) {
					return this.management.manage(second.userId(), b.id(), b.version(), b.authenticatedAt(), b.management(), target.id(), IdentityPasswordRecoveryManagement.Operation.CANCEL,
							freshCode(second), context, () -> {}).status().name();
				}
				return this.stateChanges.change(second.userId(), b.id(), b.version(), b.authenticatedAt(), b.management(), target.id(), IdentityUserStateChanges.Change.DISABLE,
						freshCode(second), context, () -> {}).name();
			});
			start.countDown();
			var delivered = issuance.get(15, TimeUnit.SECONDS);
			assertThat(mutation.get(15, TimeUnit.SECONDS)).isEqualTo(operation.equals("cancel") ? "CANCELLED" : "CHANGED");
			String status = this.jdbc.sql("SELECT status FROM iam_password_recovery WHERE user_id = :id").param("id", target.id()).query(String.class).single();
			if (operation.equals("disable")) {
				assertThat(delivered.status()).isIn(IdentityPasswordRecoveryManagement.Status.ISSUED, IdentityPasswordRecoveryManagement.Status.CONFLICT);
				assertThat(this.users.findById(target.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.DISABLED);
				assertThat(status).isEqualTo("cancelled");
			}
			else {
				assertThat(delivered.status()).isEqualTo(IdentityPasswordRecoveryManagement.Status.ISSUED);
				if (status.equals("issued")) { assertThat(this.recoveries.complete(target.id(), delivered.recovery().token(), RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED); }
				else { assertThat(this.recoveries.complete(target.id(), delivered.recovery().token(), RECOVERED_PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF); }
			}
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void administratorsCanManageTheirOwnRecoveryWithoutLosingOrGainingAuthority(String operation) throws Exception {
		var factor = administrator();
		this.recoveries.issue(factor.userId(), SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var before = evidence(session);
			long version = this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single();
			var response = manage(client, session, factor.userId(), operation, freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(operation.equals("issue") ? 200 : 204);
			assertSecurityHeaders(response);
			assertThat(evidence(session)).isEqualTo(before);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
			assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single()).isEqualTo(version);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_administrator").query(Long.class).single()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel" })
	void oppositeAdministratorTargetsUseTheSameUserLockOrder(String operation) throws Exception {
		var first = administrator();
		var second = additionalAdministrator();
		this.recoveries.issue(first.userId(), SYSTEM);
		this.recoveries.issue(second.userId(), SYSTEM);
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			var a = evidence(elevate(client, login(client, "alice"), first));
			var b = evidence(elevate(client, login(client, "second"), second));
			var start = new CountDownLatch(1);
			var change = IdentityPasswordRecoveryManagement.Operation.valueOf(operation.toUpperCase(java.util.Locale.ROOT));
			var left = executor.submit(() -> {
				start.await();
				return this.management.manage(first.userId(), a.id(), a.version(), a.authenticatedAt(), a.management(), second.userId(), change,
						freshCode(first), new TotpAuthenticationContext("internal:test", InetAddress.getByName("192.0.2.1"), UUID.randomUUID()), () -> {}).status();
			});
			var right = executor.submit(() -> {
				start.await();
				return this.management.manage(second.userId(), b.id(), b.version(), b.authenticatedAt(), b.management(), first.userId(), change,
						freshCode(second), new TotpAuthenticationContext("internal:test", InetAddress.getByName("192.0.2.2"), UUID.randomUUID()), () -> {}).status();
			});
			start.countDown();
			var expected = operation.equals("issue") ? IdentityPasswordRecoveryManagement.Status.ISSUED : IdentityPasswordRecoveryManagement.Status.CANCELLED;
			assertThat(left.get(15, TimeUnit.SECONDS)).isEqualTo(expected);
			assertThat(right.get(15, TimeUnit.SECONDS)).isEqualTo(expected);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "disable" })
	void targetChangesAfterHttpAuthorizationAreReflectedInIssuance(String change) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		var previous = this.recoveries.issue(target.id(), SYSTEM);
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String targetSession = login(client, "bobby");
			String session = elevate(client, login(client, "alice"), factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			this.pause.start();
			var request = HttpRequest.newBuilder(uri(target.id(), "issue")).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Test-Pause", "true").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (change.equals("password")) {
					var changed = post(client, "/api/me/password", targetSession, "currentPassword=" + encode(PASSWORD) + "&newPassword=" + encode(RECOVERED_PASSWORD)
							+ "&_csrf=" + encode(csrf(get(client, "/api/csrf", targetSession))));
					assertThat(changed.statusCode()).isEqualTo(204);
				}
				else { this.states.disable(target.id(), SYSTEM); }
			}
			finally { this.pause.release.countDown(); }
			var response = waiting.get(15, TimeUnit.SECONDS);
			assertThat(response.statusCode()).isEqualTo(change.equals("password") ? 200 : 409);
			assertThat(this.recoveries.complete(target.id(), previous.token(), "Twelve copper mountains behind the valley", "internal:test", UUID.randomUUID()))
					.isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
			if (change.equals("password")) {
				assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password_recovery WHERE user_id=:id").param("id", target.id()).query(Long.class).single()).isEqualTo(2);
				String token = new JsonMapper().readTree(response.body()).path("token").asText();
				assertThat(this.recoveries.complete(target.id(), token, "Twelve copper mountains behind the valley", "internal:test", UUID.randomUUID()))
						.isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
			}
		}
	}

	private record SessionEvidence(String id, long version, long authenticatedAt, IdentityAdministratorAuthentication management) { }
	private SessionEvidence evidence(String session) {
		return new SessionEvidence(session.substring(session.indexOf('=') + 1), (Long) attribute(session, IdentityBrowserSessions.CREDENTIAL_VERSION),
				(Long) attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT), (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION));
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean RequestPause recoveryManagementPause() { return new RequestPause(); }
		@Bean WebMvcConfigurer recoveryManagementPauseConfiguration(RequestPause pause) {
			return new WebMvcConfigurer() {
				@Override public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class RequestPause implements HandlerInterceptor {
		private volatile CountDownLatch entered;
		private volatile CountDownLatch release;
		private volatile boolean expireEvidence;
		private volatile boolean expirePassword;
		void start() {
			this.entered = new CountDownLatch(1); this.release = new CountDownLatch(1);
			this.expireEvidence = false; this.expirePassword = false;
		}
		@Override public boolean preHandle(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, Object handler) throws Exception {
			if ("true".equals(request.getHeader("X-Test-Pause"))) {
				this.entered.countDown();
				assertThat(this.release.await(10, TimeUnit.SECONDS)).isTrue();
				if (this.expireEvidence) {
					var session = request.getSession(false);
					long passwordTime = System.currentTimeMillis() - 1_200_000;
					session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
					var old = (IdentityAdministratorAuthentication) session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
					session.setAttribute(IdentityAdministratorSessions.AUTHENTICATION,
							new IdentityAdministratorAuthentication(old.userId(), old.factorId(), old.credentialVersion(), passwordTime, Instant.now().minusSeconds(901)));
				}
				if (this.expirePassword) { request.getSession(false).setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, System.currentTimeMillis() - 28_800_001); }
			}
			return true;
		}
	}

	private static void assertErrorResponse(HttpResponse<String> response, String code) {
		assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
		var error = new JsonMapper().readTree(response.body());
		assertThat(error.propertyNames()).containsExactlyInAnyOrder("code", "message");
		assertThat(error.path("code").asText()).isEqualTo(code);
		assertThat(error.path("message").asText()).isNotBlank();
	}

	private static String path(UUID target, String operation) { return "/api/admin/users/" + target + "/password-recovery" + (operation.equals("cancel") ? "/cancel" : ""); }
	private URI uri(UUID target, String operation) { return URI.create("https://localhost:" + this.port + path(target, operation)); }
	private HttpResponse<String> manage(HttpClient client, String session, UUID target, String operation, String code) throws Exception {
		return post(client, path(target, operation), session, form(code, csrf(get(client, "/api/csrf", session))));
	}
	private static String form(String code, String csrf) { return "code=" + encode(code) + "&_csrf=" + encode(csrf); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action AND source IN ('browser:admin-password-recovery-issue', 'browser:admin-password-recovery-cancel')").param("action", action).query(Long.class).single(); }
	private IdentityUser activeUser(String name) {
		var user = this.users.create(name, "Private Name", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(user.id()).orElseThrow();
	}
	private IdentityTotpEnrollment additionalAdministrator() {
		var user = activeUser("second");
		var factor = TotpTestSupport.distinctEnrollment(() -> this.totps.beginEnrollment(user.id(), SYSTEM));
		assertThat(this.totps.confirmEnrollment(user.id(), factor.factorId(), otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), context())).isTrue();
		// Fixture membership represents another authorized administrator without adding a grant endpoint.
		this.jdbc.sql("INSERT INTO iam_administrator(user_id) VALUES (:id)").param("id", user.id()).update();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step = last_used_step - 1 WHERE user_id = :id").param("id", user.id()).update();
		return factor;
	}
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
	private void setManagementDeadline(String session, long deadline) {
		var evidence = (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
		long passwordTime = System.currentTimeMillis() - 1_200_000;
		replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
		replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION,
				new IdentityAdministratorAuthentication(evidence.userId(), evidence.factorId(), evidence.credentialVersion(), passwordTime, Instant.ofEpochMilli(deadline - 900_000)));
	}
	private void setPasswordDeadline(String session, long deadline) {
		var evidence = (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
		long passwordTime = deadline - 28_800_000;
		replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
		replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION,
				new IdentityAdministratorAuthentication(evidence.userId(), evidence.factorId(), evidence.credentialVersion(), passwordTime, evidence.verifiedAt()));
	}
	private IdentityTotpEnrollment administrator() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), context()).orElseThrow();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step = last_used_step - 1 WHERE user_id = :id").param("id", userId).update();
		return factor;
	}
	private String login(HttpClient client, String username) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(username, PASSWORD, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}
	private String elevate(HttpClient client, String session, IdentityTotpEnrollment factor) throws Exception {
		var response = post(client, "/admin/mfa", session, "code=" + otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-password-recovery-management-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
