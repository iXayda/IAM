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
import com.ixayda.iam.dto.IdentityUserStateChangeRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityPasswordRecoveries;
import com.ixayda.iam.service.IdentityTotps;
import com.ixayda.iam.service.IdentityUserSetups;
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
@Import({ PostgreSqlTestConfiguration.class, IdentityUserStateChangeIntegrationTests.ConcurrentRequests.class })
class IdentityUserStateChangeIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:user-state-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityPasswordRecoveries recoveries;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityUserStateChanges changes;
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
	void disableRevokesAllTargetSessionsAndRecoveryProofWithoutChangingAnotherIdentity() throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		var proof = this.recoveries.issue(target.id(), SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String first = login(client, "bobby");
			String second = login(client, "bobby");
			Object management = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			var response = change(client, session, target.id(), "disable", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.body()).isEmpty();
			assertSecurityHeaders(response);
			assertThat(this.users.findById(target.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.DISABLED);
			assertThat(get(client, "/api/me", first).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", second).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isEqualTo(management);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(this.recoveries.complete(target.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
			var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = 'user_disabled' AND target_user_id = :id")
					.param("id", target.id()).query().singleRow();
			assertThat(event).containsEntry("actor", "user:" + factor.userId()).containsEntry("source", "browser:admin-user-disable");
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE correlation_id = :id AND action IN ('totp_authenticated', 'password_recovery_cancelled', 'browser_sessions_revoked', 'user_disabled')")
					.param("id", event.get("correlation_id")).query(Long.class).single()).isEqualTo(4);
		}
	}

	@ParameterizedTest
	@ValueSource(booleans = { true, false })
	void enableRestoresOnlyTheAppropriateStateWithoutRevivingSessionsOrSetupProof(boolean opened) throws Exception {
		var factor = administrator();
		var target = opened ? activeUser("bobby") : this.users.create("bobby", "Bob", SYSTEM);
		var proof = opened ? null : this.setups.issue(target.id(), SYSTEM);
		try (var client = client()) {
			String oldSession = opened ? login(client, "bobby") : null;
			this.states.disable(target.id(), SYSTEM);
			String session = elevate(client, login(client, "alice"), factor);
			assertThat(change(client, session, target.id(), "enable", freshCode(factor)).statusCode()).isEqualTo(204);
			assertThat(this.users.findById(target.id()).orElseThrow().status()).isEqualTo(opened ? IdentityUser.Status.ACTIVE : IdentityUser.Status.PENDING);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", target.id().toString()).query(Long.class).single()).isZero();
			if (opened) {
				assertThat(get(client, "/api/me", oldSession).statusCode()).isEqualTo(401);
				assertThat(get(client, "/api/me", login(client, "bobby")).statusCode()).isEqualTo(200);
			}
			else { assertThatThrownBy(() -> this.setups.complete(target.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID())).isInstanceOf(IllegalArgumentException.class); }
			assertThat(events("user_enabled")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "disable", "enable" })
	void unchangedOperationsConsumeFreshCodeWithoutDuplicatingStateEventsOrVersions(String operation) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		if (operation.equals("disable")) { this.states.disable(target.id(), SYSTEM); }
		long version = this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", target.id()).query(Long.class).single();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			assertThat(change(client, session, target.id(), operation, code).statusCode()).isEqualTo(204);
			assertThat(change(client, session, target.id(), operation, code).statusCode()).isEqualTo(400);
			assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", target.id()).query(Long.class).single()).isEqualTo(version);
			assertThat(events("user_disabled") + events("user_enabled")).isZero();
		}
	}

	@Test
	void lastAdministratorProtectionConsumesTheVerifiedCodeAndKeepsTheCurrentSession() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			var response = change(client, session, factor.userId(), "disable", code);
			assertThat(response.statusCode()).isEqualTo(409);
			assertSecurityHeaders(response);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
			assertThat(this.users.findById(factor.userId()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(events("last_administrator_protected")).isEqualTo(1);
			assertThat(events("user_disabled")).isZero();
			assertThat(change(client, session, factor.userId(), "disable", code).statusCode()).isEqualTo(400);
		}
	}

	@Test
	void selfDisableWithAnotherUsableAdministratorClearsCookieAndCannotResurrectTheSession() throws Exception {
		var factor = administrator();
		additionalAdministrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String another = login(client, "alice");
			var response = change(client, session, factor.userId(), "disable", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(204);
			assertSecurityHeaders(response);
			assertThat(response.headers().allValues("Set-Cookie")).anyMatch(value -> value.startsWith("__Host-IAMSESSION=") && value.contains("Max-Age=0"));
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", factor.userId().toString()).query(Long.class).single()).isZero();
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", another).statusCode()).isEqualTo(401);
			assertThat(events("user_disabled")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "disable", "enable" })
	void unknownTargetsAreOnlyDisclosedAfterFreshTotpVerification(String operation) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			UUID target = UUID.randomUUID();
			assertThat(change(client, session, target, operation, "invalid").statusCode()).isEqualTo(400);
			String code = freshCode(factor);
			assertThat(change(client, session, target, operation, code).statusCode()).isEqualTo(404);
			assertThat(change(client, session, target, operation, code).statusCode()).isEqualTo(400);
			assertThat(events("user_disabled") + events("user_enabled")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "disable", "enable" })
	void anonymousOrdinaryAndPasswordOnlyAdministratorRequestsCannotChangeUsers(String operation) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			var token = get(client, "/api/csrf", null);
			assertThat(post(client, path(target.id(), operation), cookie(token), form(freshCode(factor), csrf(token))).statusCode()).isEqualTo(401);
			assertThat(change(client, login(client, "bobby"), target.id(), operation, freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(change(client, login(client, "alice"), target.id(), operation, freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(events("user_disabled") + events("user_enabled")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "disable,&code=000000", "enable,&_csrf=duplicate", "disable,&actor=system", "enable,&status=ACTIVE", "disable,&userId=other", "enable,&password=forbidden" })
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
	@ValueSource(strings = { "disable", "enable" })
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
			assertThat(post(client, "/api/admin/users/1-1-1-1-1/" + operation, session, body).statusCode()).isEqualTo(400);
			assertThat(lastStep(factor)).isEqualTo(step);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "disable", "enable" })
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
			assertThat(client.send(correct, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
		}
	}

	@Test
	void wrongCodesUseTheSharedBudgetAndAnMfaCodeCannotAuthorizeAStateChange() throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertThat(change(client, session, target.id(), "disable", otp(factor, lastStep(factor))).statusCode()).isEqualTo(400);
			for (int i = 0; i < 4; i++) { assertThat(change(client, session, target.id(), "disable", "invalid").statusCode()).isEqualTo(400); }
			assertThat(change(client, session, target.id(), "disable", freshCode(factor)).statusCode()).isEqualTo(429);
			assertThat(this.totps.verify(factor.userId(), freshCode(factor), context())).isEmpty();
			assertThat(this.users.findById(target.id())).contains(target);
		}
	}

	@Test
	void concurrentStateChangesCannotConsumeOneCodeForTwoTargets() throws Exception {
		var factor = administrator();
		var firstTarget = activeUser("bobby");
		var secondTarget = activeUser("charlie");
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return post(client, path(firstTarget.id(), "disable"), session, body); });
			var second = executor.submit(() -> { start.await(); return post(client, path(secondTarget.id(), "disable"), session, body); });
			start.countDown();
			assertThat(List.of(first.get(20, TimeUnit.SECONDS).statusCode(), second.get(20, TimeUnit.SECONDS).statusCode())).containsExactlyInAnyOrder(204, 400);
			assertThat(events("user_disabled")).isEqualTo(1);
		}
	}

	@Test
	void administratorsTargetingEachOtherFromDifferentSourcesSerializeWithoutDeadlockOrLosingBoth() throws Exception {
		var firstFactor = administrator();
		var secondFactor = additionalAdministrator();
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String firstSession = elevate(client, login(client, "alice"), firstFactor);
			String secondSession = elevate(client, login(client, "second"), secondFactor);
			var firstEvidence = evidence(firstSession);
			var secondEvidence = evidence(secondSession);
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return directChange(firstFactor, firstEvidence, secondFactor.userId(), "192.0.2.1"); });
			var second = executor.submit(() -> { start.await(); return directChange(secondFactor, secondEvidence, firstFactor.userId(), "192.0.2.2"); });
			start.countDown();
			assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS)))
					.containsExactlyInAnyOrder(IdentityUserStateChanges.Status.CHANGED, IdentityUserStateChanges.Status.INVALID_SESSION);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user WHERE status = 'active'").query(Long.class).single()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@CsvSource({ "disable,membership,403", "disable,factor,403", "disable,version,401", "disable,disabled,401", "disable,session,401", "disable,mfa-expiry,403", "disable,password-expiry,401", "enable,membership,403", "enable,factor,403", "enable,version,401", "enable,disabled,401", "enable,session,401", "enable,mfa-expiry,403", "enable,password-expiry,401" })
	void authorityAndSessionChangesAfterHttpAuthorizationAreRecheckedBeforeMutation(String operation, String fault, int expected) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		if (operation.equals("enable")) { this.states.disable(target.id(), SYSTEM); }
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
			assertThat(this.users.findById(target.id()).orElseThrow().status()).isEqualTo(operation.equals("enable") ? IdentityUser.Status.DISABLED : IdentityUser.Status.ACTIVE);
			assertThat(events("user_disabled")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "disable,audit", "disable,silent-audit", "disable,deferred-audit", "disable,state", "disable,silent-state", "disable,session", "disable,silent-session", "disable,deferred-session", "disable,revoke", "disable,silent-revoke", "enable,audit", "enable,silent-audit", "enable,state", "enable,silent-state", "enable,session", "enable,deferred-state" })
	void storageAndAuditFailuresRollBackStateProofsSessionsCodeAndSuccessEvents(String operation, String fault) throws Exception {
		var factor = administrator();
		var target = activeUser("bobby");
		if (operation.equals("enable")) { this.states.disable(target.id(), SYSTEM); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String targetSession = operation.equals("disable") ? login(client, "bobby") : null;
			if (operation.equals("disable")) { this.recoveries.issue(target.id(), SYSTEM); }
			String body = form(freshCode(factor), csrf(get(client, "/api/csrf", session)));
			long step = lastStep(factor);
			String table = fault.contains("audit") ? "iam_security_audit" : fault.contains("state") ? "iam_user" : "iam_browser_session";
			String guard = fault.contains("audit") ? "IF NEW.source <> 'browser:admin-user-" + operation + "' OR NEW.action <> 'user_" + (operation.equals("disable") ? "disabled" : "enabled") + "' THEN RETURN NEW; END IF; "
					: fault.contains("state") ? "IF NEW.id <> '" + target.id() + "'::uuid THEN RETURN NEW; END IF; " : "";
			String action = fault.contains("revoke") ? "DELETE" : fault.contains("audit") ? "INSERT" : "UPDATE";
			this.jdbc.sql("CREATE FUNCTION user_state_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard
					+ (fault.startsWith("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected state workflow failure';") + " END $$").update();
			this.jdbc.sql((fault.startsWith("deferred") ? "CREATE CONSTRAINT TRIGGER user_state_fault AFTER " : "CREATE TRIGGER user_state_fault BEFORE ")
					+ action + " ON " + table + (fault.startsWith("deferred") ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION user_state_fault()").update();
			try {
				var response = post(client, path(target.id(), operation), session, body);
				assertThat(response.statusCode()).isEqualTo(503);
				assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
				assertSecurityHeaders(response);
			}
			finally { this.jdbc.sql("DROP FUNCTION user_state_fault() CASCADE").update(); }
			assertThat(this.users.findById(target.id()).orElseThrow().status()).isEqualTo(operation.equals("disable") ? IdentityUser.Status.ACTIVE : IdentityUser.Status.DISABLED);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(events("user_disabled") + events("user_enabled")).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE source = :source AND outcome = 'success'").param("source", "browser:admin-user-" + operation).query(Long.class).single()).isZero();
			if (targetSession != null) {
				assertThat(get(client, "/api/me", targetSession).statusCode()).isEqualTo(200);
				assertThat(this.jdbc.sql("SELECT status FROM iam_password_recovery WHERE user_id = :id").param("id", target.id()).query(String.class).single()).isEqualTo("issued");
			}
			assertThat(post(client, path(target.id(), operation), session, body).statusCode()).isEqualTo(204);
		}
	}

	@ParameterizedTest
	@CsvSource({ "false,mfa,audit", "false,password,audit", "true,mfa,audit", "true,password,audit", "false,mfa,session", "false,password,session", "true,mfa,session", "true,password,session",
			"false,idle,audit", "true,idle,audit", "false,idle,session", "true,idle,session" })
	void expiryWhileSavingSessionOrAuditRollsBackEvenAnIntentionalSelfDisable(boolean self, String deadlineType, String waitingAt) throws Exception {
		var factor = administrator();
		UUID target = self ? factor.userId() : activeUser("bobby").id();
		long credentialVersion = this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id")
				.param("id", target).query(Long.class).single();
		if (self) { additionalAdministrator(); }
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
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173802)"); }
			String guard = waitingAt.equals("audit") ? "IF NEW.action <> 'user_disabled' OR NEW.source <> 'browser:admin-user-disable' THEN RETURN NEW; END IF; "
					: "IF NOT EXISTS (SELECT 1 FROM iam_security_audit WHERE action = 'totp_authenticated' AND source = 'browser:admin-user-disable') THEN RETURN NEW; END IF; ";
			this.jdbc.sql("CREATE FUNCTION user_state_deadline_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173802); RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER user_state_deadline_wait BEFORE " + (waitingAt.equals("audit") ? "INSERT ON iam_security_audit" : "UPDATE ON iam_browser_session") + " FOR EACH ROW EXECUTE FUNCTION user_state_deadline_wait()").update();
			var waiting = executor.submit(() -> post(client, path(target, "disable"), session, body));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))").param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.rollback();
				var response = waiting.get(15, TimeUnit.SECONDS);
				assertThat(response.statusCode()).isEqualTo(503);
				assertSecurityHeaders(response);
			}
			finally {
				blocker.rollback();
				this.jdbc.sql("DROP FUNCTION user_state_deadline_wait() CASCADE").update();
			}
			assertThat(this.users.findById(target).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id")
					.param("id", target).query(Long.class).single()).isEqualTo(credentialVersion);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(events("user_disabled")).isZero();
			// Spring Session may remove the genuinely idle-expired caller after the business rollback.
			if (deadlineType.equals("idle")) { assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401); }
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE session_id = :id")
					.param("id", session.substring(session.indexOf('=') + 1)).query(Long.class).single()).isEqualTo(deadlineType.equals("idle") ? 0 : 1);
		}
	}

	@Test
	void callerTransactionsAreRejectedAndRequestTextDoesNotExposeCodes() {
		var factor = administrator();
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.changes.change(factor.userId(), "untrusted", 1, System.currentTimeMillis(), null, UUID.randomUUID(), IdentityUserStateChanges.Change.DISABLE,
						"123456", context(), () -> {}))).isInstanceOf(IllegalStateException.class).hasMessageContaining("independent transaction");
		assertThat(new IdentityUserStateChangeRequest("123456").toString()).doesNotContain("123456");
	}

	private record SessionEvidence(String id, long version, long authenticatedAt, IdentityAdministratorAuthentication management) { }
	private SessionEvidence evidence(String session) {
		return new SessionEvidence(session.substring(session.indexOf('=') + 1), (Long) attribute(session, IdentityBrowserSessions.CREDENTIAL_VERSION),
				(Long) attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT), (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION));
	}
	private IdentityUserStateChanges.Status directChange(IdentityTotpEnrollment factor, SessionEvidence session, UUID target, String address) throws Exception {
		return this.changes.change(factor.userId(), session.id(), session.version(), session.authenticatedAt(), session.management(), target, IdentityUserStateChanges.Change.DISABLE,
				freshCode(factor), new TotpAuthenticationContext("internal:test", InetAddress.getByName(address), UUID.randomUUID()), () -> {});
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean RequestPause stateChangePause() { return new RequestPause(); }
		@Bean WebMvcConfigurer stateChangePauseConfiguration(RequestPause pause) {
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

	private static String path(UUID target, String operation) { return "/api/admin/users/" + target + "/" + operation; }
	private URI uri(UUID target, String operation) { return URI.create("https://localhost:" + this.port + path(target, operation)); }
	private HttpResponse<String> change(HttpClient client, String session, UUID target, String operation, String code) throws Exception {
		return post(client, path(target, operation), session, form(code, csrf(get(client, "/api/csrf", session))));
	}
	private static String form(String code, String csrf) { return "code=" + encode(code) + "&_csrf=" + encode(csrf); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action AND source IN ('browser:admin-user-disable', 'browser:admin-user-enable')").param("action", action).query(Long.class).single(); }
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
			Path path = Files.createTempFile("iam-user-state-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
