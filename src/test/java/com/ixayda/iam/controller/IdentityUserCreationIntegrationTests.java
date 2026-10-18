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

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.dto.IdentityUserCreateRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityTotps;
import com.ixayda.iam.service.IdentityUserCreations;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import com.jayway.jsonpath.JsonPath;

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
@Import({ PostgreSqlTestConfiguration.class, IdentityUserCreationIntegrationTests.ConcurrentRequests.class })
class IdentityUserCreationIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:user-creation-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityUserCreations creations;
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
	void createsOnlyTheRequestedPendingIdentityAndRecordsTrustedAttribution() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long passwordTime = (Long) attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			Object management = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			String code = freshCode(factor);
			var response = create(client, session, "BOBBY", " Cafe\u0301 用户 😀 ", code);
			assertThat(response.statusCode()).isEqualTo(201);
			assertSecurityHeaders(response);
			Map<String, Object> body = JsonPath.read(response.body(), "$");
			assertThat(body).containsOnlyKeys("id", "username", "displayName", "status", "createdAt")
					.containsEntry("username", "bobby").containsEntry("displayName", " Café 用户 😀 ").containsEntry("status", "PENDING");
			UUID target = UUID.fromString((String) body.get("id"));
			assertThat(response.headers().firstValue("Location")).contains("/api/admin/users/" + target);
			assertThat(get(client, "/api/admin/users/" + target, session).statusCode()).isEqualTo(200);
			for (String table : List.of("iam_password", "iam_user_setup", "iam_user_totp", "iam_administrator")) {
				assertThat(this.jdbc.sql("SELECT count(*) FROM " + table + " WHERE user_id = :id").param("id", target).query(Long.class).single()).isZero();
			}
			var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = 'user_created' AND target_user_id = :id").param("id", target).query().singleRow();
			assertThat(event).containsEntry("actor", "user:" + factor.userId()).containsEntry("source", "browser:admin-user-create").containsEntry("outcome", "success");
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'totp_authenticated' AND correlation_id = :id")
					.param("id", event.get("correlation_id")).query(Long.class).single()).isEqualTo(1);
			assertThat(response.body()).doesNotContain(PASSWORD, factor.secret(), "credentialVersion");
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isEqualTo(management);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		}
	}

	@Test
	void aSuccessfulCreationDoesNotActivateTheAccountAndTheExistingSetupWorkflowRemainsUsable() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var response = create(client, session, "bobby", "Bob", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(201);
			UUID target = UUID.fromString(JsonPath.read(response.body(), "$.id"));
			var proof = this.setups.issue(target, SYSTEM);
			this.setups.complete(target, proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
			String user = login(client, "bobby");
			assertThat(get(client, "/api/me", user).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/admin/users", user).statusCode()).isEqualTo(403);
		}
	}

	@Test
	void existingUsernamesReturn409WithoutReplacingIdentityAndRollbackTheUnusedAttempt() throws Exception {
		var factor = administrator();
		var existing = this.users.create("bobby", "Original", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			long step = lastStep(factor);
			var response = create(client, session, "BOBBY", "Replacement", code);
			assertThat(response.statusCode()).isEqualTo(409);
			assertThat(response.body()).isEqualTo("Username unavailable");
			assertSecurityHeaders(response);
			assertThat(this.users.findById(existing.id())).contains(existing);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
			assertThat(create(client, session, "charlie", "Charlie", code).statusCode()).isEqualTo(201);
		}
	}

	@ParameterizedTest
	@CsvSource({ "ab, Bob", "has space, Bob", "bobby, '   '" })
	void invalidNamesAreRejectedWithoutConsumingTheOperationCode(String username, String displayName) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			assertRejected(create(client, session, username, displayName, freshCode(factor)), 400);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
		}
	}

	@Test
	void acceptsMaximumNamesAndRejectsOverlongOrControlContainingNames() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			assertRejected(create(client, session, "a".repeat(65), "Bob", code), 400);
			assertRejected(create(client, session, "bobby", "😀".repeat(129), code), 400);
			assertRejected(create(client, session, "bobby", "Bob\n", code), 400);
			assertRejected(create(client, session, "bobby", "Bob\u0000", code), 400);
			var response = create(client, session, "A".repeat(64), "😀".repeat(128), code);
			assertThat(response.statusCode()).isEqualTo(201);
			assertThat((String) JsonPath.read(response.body(), "$.username")).isEqualTo("a".repeat(64));
			assertThat((String) JsonPath.read(response.body(), "$.displayName")).isEqualTo("😀".repeat(128));
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "username", "displayName", "code" })
	void missingFieldsCannotBePopulatedFromHeaders(String missing) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var values = new java.util.LinkedHashMap<>(Map.of("username", "bobby", "displayName", "Bob", "code", freshCode(factor), "_csrf", csrf(get(client, "/api/csrf", session))));
			String header = values.remove(missing);
			String body = values.entrySet().stream().map(e -> encode(e.getKey()) + "=" + encode(e.getValue())).collect(java.util.stream.Collectors.joining("&"));
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header(missing, header)
					.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 400);
			assertThat(creationEvents()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "&username=other", "&displayName=Other", "&code=000000", "&actor=system", "&status=ACTIVE", "&password=forbidden", "&userId=00000000-0000-0000-0000-000000000001" })
	void repeatedAndUnapprovedFieldsCannotChangeTheCreationTargetOrCaller(String extra) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			var response = post(client, "/api/admin/users", session, creationForm("bobby", "Bob", freshCode(factor), csrf(get(client, "/api/csrf", session))) + extra);
			assertThat(response.statusCode()).isEqualTo(400);
			assertSecurityHeaders(response);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
		}
	}

	@Test
	void queryParametersJsonAndMissingCsrfAreRejectedBeforeAnyMutation() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			String form = creationForm("bobby", "Bob", freshCode(factor), csrf(get(client, "/api/csrf", session)));
			assertThat(post(client, "/api/admin/users?username=bobby", session, form).statusCode()).isEqualTo(400);
			assertThat(post(client, "/api/admin/users", session, "username=bobby&displayName=Bob&code=" + freshCode(factor)).statusCode()).isEqualTo(403);
			var json = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
		}
	}

	@Test
	void csrfCanBeSuppliedThroughTheStandardHeader() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
					.POST(HttpRequest.BodyPublishers.ofString("username=bobby&displayName=Bob&code=" + freshCode(factor))).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(201);
		}
	}

	@Test
	void anUnacceptableResponseFormatIsRejectedBeforeUserCreationOrCodeConsumption() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			String form = creationForm("bobby", "Bob", freshCode(factor), csrf(get(client, "/api/csrf", session)));
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("Accept", "text/plain").POST(HttpRequest.BodyPublishers.ofString(form)).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(406);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
			assertThat(post(client, "/api/admin/users", session, form).statusCode()).isEqualTo(201);
		}
	}

	@Test
	void anonymousOrdinaryAndPasswordOnlyAdministratorRequestsCannotCreateUsers() throws Exception {
		var factor = administrator();
		var user = this.users.create("ordinary", "User", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			assertThat(post(client, "/api/admin/users", cookie(page), creationForm("bobby", "Bob", freshCode(factor), csrf(page))).statusCode()).isEqualTo(401);
			String ordinary = login(client, "ordinary");
			assertThat(create(client, ordinary, "bobby", "Bob", freshCode(factor)).statusCode()).isEqualTo(403);
			String passwordOnly = login(client, "alice");
			assertThat(create(client, passwordOnly, "bobby", "Bob", freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(creationEvents()).isZero();
		}
	}

	@Test
	void theMfaCodeCannotBeReusedForCreationAndACreationCodeCannotAuthorizeAnotherTarget() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertRejected(create(client, session, "bobby", "Bob", otp(factor, lastStep(factor))), 400);
			String code = freshCode(factor);
			assertThat(create(client, session, "bobby", "Bob", code).statusCode()).isEqualTo(201);
			assertRejected(create(client, session, "charlie", "Charlie", code), 400);
			assertThat(this.users.findByUsername("charlie")).isEmpty();
			assertThat(creationEvents()).isEqualTo(1);
		}
	}

	@Test
	void wrongCodesConsumeTheSharedBudgetAndThrottleEvenACorrectCode() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			for (int i = 0; i < 5; i++) { assertRejected(create(client, session, "bobby", "Bob", "invalid"), 400); }
			assertRejected(create(client, session, "bobby", "Bob", freshCode(factor)), 429);
			assertThat(this.jdbc.sql("SELECT failures FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Integer.class).single()).isEqualTo(5);
			assertThat(this.totps.verify(factor.userId(), freshCode(factor), context())).isEmpty();
			assertThat(creationEvents()).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "membership, 403", "mfa-expiry, 403", "factor, 403", "password-expiry, 401", "disabled, 401", "version, 401", "session, 401" })
	void permissionAndSessionChangesAfterHttpAuthorizationAreRecheckedInsideTheWorkflow(String operation, int expected) throws Exception {
		var factor = administrator();
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = creationForm("bobby", "Bob", freshCode(factor), csrf(get(client, "/api/csrf", session)));
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Test-Pause", "true").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (operation.equals("membership")) { this.jdbc.sql("DELETE FROM iam_administrator").update(); }
				else if (operation.equals("mfa-expiry")) {
					// Replace the request's loaded server evidence with an expired value before the workflow starts.
					this.pause.expireEvidence = true;
				}
				else if (operation.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
				else if (operation.equals("factor")) { this.jdbc.sql("DELETE FROM iam_user_totp").update(); }
				else if (operation.equals("password-expiry")) { this.pause.expirePassword = true; }
				else if (operation.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled'").update(); }
				else { this.jdbc.sql("DELETE FROM iam_browser_session").update(); }
			}
			finally { this.pause.release.countDown(); }
			var response = waiting.get(15, TimeUnit.SECONDS);
			assertThat(response.statusCode()).isEqualTo(expected);
			assertErrorResponse(response, expected == 401 ? "UNAUTHENTICATED" : "FORBIDDEN");
			assertThat(creationEvents()).isZero();
		}
	}

	@Test
	void concurrentRequestsCannotUseOneCodeToCreateTwoDifferentUsers() throws Exception {
		var factor = administrator();
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			String token = csrf(get(client, "/api/csrf", session));
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return post(client, "/api/admin/users", session, creationForm("bobby", "Bob", code, token)); });
			var second = executor.submit(() -> { start.await(); return post(client, "/api/admin/users", session, creationForm("charlie", "Charlie", code, token)); });
			start.countDown();
			assertThat(List.of(first.get(20, TimeUnit.SECONDS).statusCode(), second.get(20, TimeUnit.SECONDS).statusCode())).containsExactlyInAnyOrder(201, 400);
			assertThat(creationEvents()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@CsvSource({ "commit, 409", "rollback, 201" })
	void aConcurrentUsernameInsertUsesTheDatabaseConstraintAndPreservesAtomicity(String completion, int expected) throws Exception {
		var factor = administrator();
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			String session = elevate(client, login(client, "alice"), factor);
			String form = creationForm("BOBBY", "From administrator", freshCode(factor), csrf(get(client, "/api/csrf", session)));
			long step = lastStep(factor);
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.prepareStatement("INSERT INTO iam_user(id, username, display_name) VALUES (?, 'bobby', 'Concurrent user')")) {
				statement.setObject(1, UUID.randomUUID()); statement.executeUpdate();
			}
			var waiting = executor.submit(() -> post(client, "/api/admin/users", session, form));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
						.param("pid", pid).query(Boolean.class).single());
				if (completion.equals("commit")) { blocker.commit(); } else { blocker.rollback(); }
				assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(expected);
			}
			finally { blocker.rollback(); }
			assertThat(this.users.findByUsername("bobby").orElseThrow().displayName()).isEqualTo(expected == 201 ? "From administrator" : "Concurrent user");
			assertThat(creationEvents()).isEqualTo(expected == 201 ? 1 : 0);
			if (expected == 409) { assertThat(lastStep(factor)).isEqualTo(step); }
		}
	}

	@ParameterizedTest
	@CsvSource({ "user, mfa, 403", "session, mfa, 403", "user, idle, 401", "session, idle, 401" })
	void expirationsAreRecheckedAfterWaitingForTheUserOrSessionLock(String locked, String deadlineType, int expected) throws Exception {
		var factor = administrator();
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			String session = elevate(client, login(client, "alice"), factor);
			String form = creationForm("bobby", "Bob", freshCode(factor), csrf(get(client, "/api/csrf", session)));
			long step = lastStep(factor);
			long deadline = System.currentTimeMillis() + 2000;
			if (deadlineType.equals("mfa")) {
				setManagementDeadline(session, deadline);
			}
			else { this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :deadline").param("deadline", deadline).update(); }
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.prepareStatement(locked.equals("user") ? "SELECT id FROM iam_user WHERE id = ? FOR UPDATE" : "SELECT session_id FROM iam_browser_session WHERE session_id = ? FOR UPDATE")) {
				statement.setObject(1, locked.equals("user") ? factor.userId() : session.substring(session.indexOf('=') + 1)); statement.executeQuery().close();
			}
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Test-Pause", "true").timeout(Duration.ofSeconds(20)).POST(HttpRequest.BodyPublishers.ofString(form)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				// The request must pass HTTP authorization before waiting inside the workflow.
				assertThat(this.pause.entered.await(5, TimeUnit.SECONDS)).isTrue();
				this.pause.release.countDown();
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
						.param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(expected);
			}
			finally { this.pause.release.countDown(); blocker.rollback(); }
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
			assertThat(this.users.findByUsername("bobby")).isEmpty();
			if (deadlineType.equals("mfa")) {
				assertThat(this.jdbc.sql("SELECT source FROM iam_security_audit WHERE action = 'admin_access_denied'")
						.query(String.class).list()).containsExactly("browser:admin-user-create");
			}
		}
	}

	@ParameterizedTest
	@CsvSource({ "username, mfa", "audit, mfa", "session, mfa", "username, password", "audit, password", "session, password",
			"username, idle", "audit, idle", "session, idle" })
	void authenticationExpiryDuringCreationOrPersistenceRollsBackTheUserCodeAndSuccessEvents(String waitingAt, String deadlineType) throws Exception {
		var factor = administrator();
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			Object management = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			String form = creationForm("bobby", "Bob", freshCode(factor), token);
			long step = lastStep(factor);
			long deadline = System.currentTimeMillis() + 3000;
			if (deadlineType.equals("mfa")) { setManagementDeadline(session, deadline); }
			else if (deadlineType.equals("idle")) {
				this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
						.param("expiry", deadline).param("id", session.substring(session.indexOf('=') + 1)).update();
			}
			else { setPasswordDeadline(session, deadline); }
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			if (waitingAt.equals("username")) {
				try (var statement = blocker.prepareStatement("INSERT INTO iam_user(id, username, display_name) VALUES (?, 'bobby', 'Blocker')")) {
					statement.setObject(1, UUID.randomUUID()); statement.executeUpdate();
				}
			}
			else {
				try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173801)"); }
				String guard = waitingAt.equals("audit")
						? "IF NEW.action <> 'user_created' OR NEW.source <> 'browser:admin-user-create' THEN RETURN NEW; END IF; "
						: "IF NOT EXISTS (SELECT 1 FROM iam_security_audit WHERE action = 'user_created' AND source = 'browser:admin-user-create') THEN RETURN NEW; END IF; ";
				this.jdbc.sql("CREATE FUNCTION user_creation_deadline_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard
						+ "PERFORM pg_advisory_xact_lock(72173801); RETURN NEW; END $$").update();
				this.jdbc.sql("CREATE TRIGGER user_creation_deadline_wait BEFORE "
						+ (waitingAt.equals("audit") ? "INSERT ON iam_security_audit" : "UPDATE ON iam_browser_session")
						+ " FOR EACH ROW EXECUTE FUNCTION user_creation_deadline_wait()").update();
			}
			var waiting = executor.submit(() -> post(client, "/api/admin/users", session, form));
			try {
				// Every selected wait follows operation-code verification, not a denied request's final session save.
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
						.param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.rollback();
				var response = waiting.get(15, TimeUnit.SECONDS);
				assertThat(response.statusCode()).isEqualTo(503);
				assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
				assertThat(response.headers().firstValue("Location")).isEmpty();
				assertSecurityHeaders(response);
			}
			finally {
				blocker.rollback();
				if (!waitingAt.equals("username")) { this.jdbc.sql("DROP FUNCTION user_creation_deadline_wait() CASCADE").update(); }
			}
			assertThat(this.users.findByUsername("bobby")).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE source = 'browser:admin-user-create' AND outcome = 'success'")
					.query(Long.class).single()).isZero();
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(deadlineType.equals("mfa") ? 403 : 401);
			if (deadlineType.equals("mfa")) {
				// Restoring the fixture's original, still-valid management evidence allows the unused code to be retried.
				replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
				replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION, management);
				assertThat(post(client, "/api/admin/users", session, form).statusCode()).isEqualTo(201);
			}
		}
	}

	@Test
	void anUnchangedSessionIsNotSavedAgainAfterTheCreationTransaction() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String form = creationForm("bobby", "Bob", freshCode(factor), csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("CREATE SEQUENCE user_creation_session_saves").update();
			this.jdbc.sql("CREATE FUNCTION user_creation_second_save() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('user_creation_session_saves') > 1 THEN RAISE EXCEPTION 'unexpected repeated session write'; END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER user_creation_second_save BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION user_creation_second_save()").update();
			try {
				var response = post(client, "/api/admin/users", session, form);
				assertThat(response.statusCode()).isEqualTo(201);
				assertSecurityHeaders(response);
				assertThat(this.users.findByUsername("bobby")).isPresent();
				assertThat(creationEvents()).isEqualTo(1);
				assertThat(this.jdbc.sql("SELECT last_value FROM user_creation_session_saves").query(Long.class).single()).isEqualTo(1);
				// A new request must still validate and save its freshly loaded session.
				assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(503);
				assertThat(this.jdbc.sql("SELECT last_value FROM user_creation_session_saves").query(Long.class).single()).isEqualTo(2);
			}
			finally {
				this.jdbc.sql("DROP FUNCTION user_creation_second_save() CASCADE").update();
				this.jdbc.sql("DROP SEQUENCE user_creation_session_saves").update();
			}
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent" })
	void rejectedCodeAuditFailuresRollbackFailureBudgetsAndDoNotCreateAUser(String mode) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			this.jdbc.sql("CREATE FUNCTION user_creation_failure_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source = 'browser:admin-user-create' AND NEW.action = 'totp_auth_failed' THEN "
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected failure audit error';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER user_creation_failure_audit BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION user_creation_failure_audit()").update();
			try {
				var response = post(client, "/api/admin/users", session, creationForm("bobby", "Bob", "invalid", token));
				assertThat(response.statusCode()).isEqualTo(503);
				assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
				assertSecurityHeaders(response);
			}
			finally { this.jdbc.sql("DROP FUNCTION user_creation_failure_audit() CASCADE").update(); }
			assertThat(this.jdbc.sql("SELECT coalesce(sum(failures), 0) FROM iam_totp_authentication_limit").query(Long.class).single()).isZero();
			assertThat(creationEvents()).isZero();
			assertThat(post(client, "/api/admin/users", session, creationForm("bobby", "Bob", freshCode(factor), token)).statusCode()).isEqualTo(201);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit", "silent-audit", "deferred-audit", "session", "silent-session", "deferred-session", "factor-audit" })
	void storageAndAuditFailuresRollbackTheUserCodeAndSuccessfulEvents(String fault) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			String form = creationForm("bobby", "Bob", code, csrf(get(client, "/api/csrf", session)));
			long step = lastStep(factor);
			boolean sessionFault = fault.contains("session");
			String table = sessionFault ? "iam_browser_session" : "iam_security_audit";
			String body = sessionFault ? "" : "IF NEW.source <> 'browser:admin-user-create' OR NEW.action <> '" + (fault.equals("factor-audit") ? "totp_authenticated" : "user_created") + "' THEN RETURN NEW; END IF; ";
			body += fault.startsWith("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected creation failure';";
			this.jdbc.sql("CREATE FUNCTION user_creation_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
			String trigger = fault.startsWith("deferred") ? "CREATE CONSTRAINT TRIGGER user_creation_fault AFTER " : "CREATE TRIGGER user_creation_fault BEFORE ";
			trigger += (sessionFault ? "UPDATE" : "INSERT") + " ON " + table + (fault.startsWith("deferred") ? " DEFERRABLE INITIALLY DEFERRED" : "");
			this.jdbc.sql(trigger + " FOR EACH ROW EXECUTE FUNCTION user_creation_fault()").update();
			try {
				var response = post(client, "/api/admin/users", session, form);
				assertThat(response.statusCode()).isEqualTo(503);
				assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
				assertThat(response.headers().firstValue("Location")).isEmpty();
				assertSecurityHeaders(response);
			}
			finally { this.jdbc.sql("DROP FUNCTION user_creation_fault() CASCADE").update(); }
			assertThat(this.users.findByUsername("bobby")).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(creationEvents()).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE source = 'browser:admin-user-create' AND outcome = 'success'").query(Long.class).single()).isZero();
			assertThat(post(client, "/api/admin/users", session, form).statusCode()).isEqualTo(201);
		}
	}

	@Test
	void callerTransactionsAreRejectedAndRequestTextNeverContainsTheCode() {
		var factor = administrator();
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.creations.create(factor.userId(), "untrusted-session", 1, System.currentTimeMillis(), null, "bobby", "Bob", "123456", context(), () -> {})))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("independent transaction");
		assertThat(new IdentityUserCreateRequest("bobby", "Bob", "123456").toString()).doesNotContain("123456", "bobby", "Bob");
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean RequestPause creationPause() { return new RequestPause(); }
		@Bean WebMvcConfigurer creationPauseConfiguration(RequestPause pause) {
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

	private String base() { return "https://localhost:" + this.port + "/api/admin/users"; }
	private HttpResponse<String> create(HttpClient client, String session, String username, String displayName, String code) throws Exception {
		return post(client, "/api/admin/users", session, creationForm(username, displayName, code, csrf(get(client, "/api/csrf", session))));
	}
	private static String creationForm(String username, String displayName, String code, String csrf) {
		return "username=" + encode(username) + "&displayName=" + encode(displayName) + "&code=" + encode(code) + "&_csrf=" + encode(csrf);
	}
	private static void assertRejected(HttpResponse<String> response, int status) {
		assertThat(response.statusCode()).isEqualTo(status);
		assertSecurityHeaders(response);
		assertThat(response.body()).isEqualTo(status == 429 ? "Verification temporarily unavailable" : "User creation rejected");
	}
	private long creationEvents() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'user_created' AND source = 'browser:admin-user-create'").query(Long.class).single(); }
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
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step = last_used_step - 1").update();
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
			Path path = Files.createTempFile("iam-user-creation-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
