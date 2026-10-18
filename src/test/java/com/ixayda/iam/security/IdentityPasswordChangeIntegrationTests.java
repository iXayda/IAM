package com.ixayda.iam.security;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.dto.IdentityPasswordChangeRequest;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAuthentications;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({ PostgreSqlTestConfiguration.class, IdentityPasswordChangeIntegrationTests.ConcurrentRequests.class })
class IdentityPasswordChangeIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = " Seven amber lanterns by the Café ";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:password-test", "internal:test", UUID.randomUUID());

	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private SessionRepository<?> repository;
	@Autowired
	private RequestPause pause;
	@MockitoSpyBean
	private IdentityAuthentications authentications;
	@MockitoSpyBean
	private PasswordHasher passwords;

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void changesOnlyTheAuthenticatedUsersPasswordAndRevokesEveryOwnedSession() throws Exception {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		String bobHash = hash(bob.id());
		try (var client = client()) {
			String current = login(client, "alice", PASSWORD);
			String other = login(client, "alice", PASSWORD);
			String bobSession = login(client, "bobby", PASSWORD);
			// More rows than a session-list page: revocation must never operate on a paginated subset.
			this.jdbc.sql("""
					INSERT INTO iam_browser_session (primary_id, session_id, creation_time, last_access_time,
					max_inactive_interval, expiry_time, principal_name)
					SELECT gen_random_uuid()::text, gen_random_uuid()::text, 1, 1, 1800, 1, :principal
					FROM generate_series(1, 120)
					""").param("principal", alice.id().toString()).update();
			String token = csrf(get(client, "/api/csrf", current));
			var response = post(client, "/api/me/password", current,
					changeForm(PASSWORD, NEW_PASSWORD, token) + "&userId=" + bob.id() + "&credentialVersion=999");
			assertThat(response.statusCode()).isEqualTo(204);
			assertSecurityHeaders(response);
			assertThat(response.body()).isEmpty();
			assertThat(response.headers().allValues("Set-Cookie")).anySatisfy(value ->
					assertThat(value).contains("__Host-IAMSESSION=", "Max-Age=0", "Secure", "HttpOnly"));
			assertThat(version(alice.id())).isEqualTo(2);
			assertThat(this.passwords.matches(NEW_PASSWORD, hash(alice.id()))).isTrue();
			assertThat(this.passwords.matches(PASSWORD, hash(alice.id()))).isFalse();
			assertThat(sessionCount(alice.id())).isZero();
			assertThat(get(client, "/api/me", current).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", other).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", bobSession).statusCode()).isEqualTo(200);
			assertThat(hash(bob.id())).isEqualTo(bobHash);
			assertThat(version(bob.id())).isEqualTo(1);
			var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('password_changed', 'browser_sessions_revoked')")
					.query().listOfRows();
			assertThat(events).hasSize(2).allSatisfy(event -> {
				assertThat(event.get("actor")).isEqualTo("user:" + alice.id());
				assertThat(event.get("target_user_id")).isEqualTo(alice.id());
				assertThat(event.get("source")).isEqualTo("browser:password-change");
				assertThat(event.get("outcome")).isEqualTo("success");
			});
			assertThat(events.getFirst().get("correlation_id")).isEqualTo(events.getLast().get("correlation_id"));
			assertThat(count("browser_session_ended")).isZero();
			var page = get(client, "/api/csrf", null);
			assertThat(post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page))).statusCode()).isEqualTo(401);
			assertThat(login(client, "alice", NEW_PASSWORD)).startsWith("__Host-IAMSESSION=");
			for (String table : List.of("iam_security_audit", "iam_password_authentication_limit")) {
				assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t").query(String.class).list())
						.allSatisfy(row -> assertThat(row).doesNotContain(PASSWORD, NEW_PASSWORD, hash(alice.id()), "127.0.0.1"));
			}
			assertThat(new IdentityPasswordChangeRequest(PASSWORD, NEW_PASSWORD).toString()).doesNotContain(PASSWORD, NEW_PASSWORD);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "both", "currentPassword", "newPassword" })
	void rejectsPasswordFieldsSuppliedOnlyByHeaders(String missingFields) throws Exception {
		String currentPassword = "Seven amber lanterns above the river";
		var alice = this.users.create("alice", "Alice", SYSTEM);
		var proof = this.setups.issue(alice.id(), SYSTEM);
		this.setups.complete(alice.id(), proof.token(), currentPassword, "internal:test", UUID.randomUUID());
		String originalHash = hash(alice.id());
		try (var client = client()) {
			String session = login(client, "alice", currentPassword);
			String other = login(client, "alice", currentPassword);
			String body = "_csrf=" + encode(csrf(get(client, "/api/csrf", session)));
			if (missingFields.equals("newPassword")) { body += "&currentPassword=" + encode(currentPassword); }
			if (missingFields.equals("currentPassword")) { body += "&newPassword=" + encode(NEW_PASSWORD); }
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/me/password"))
					.timeout(Duration.ofSeconds(20)).header("Cookie", session)
					.header("Content-Type", "application/x-www-form-urlencoded")
					.header("currentPassword", currentPassword).header("newPassword", NEW_PASSWORD)
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var rejected = client.send(request, HttpResponse.BodyHandlers.ofString());
			assertThat(rejected.statusCode()).isEqualTo(400);
			assertSecurityHeaders(rejected);
			assertThat(rejected.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(hash(alice.id())).isEqualTo(originalHash);
			assertThat(version(alice.id())).isEqualTo(1);
			assertThat(sessionCount(alice.id())).isEqualTo(2);
			assertThat(count("password_changed")).isZero();
			assertThat(count("browser_sessions_revoked")).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/me", other).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void changesPasswordUsingFormFieldsDespiteConflictingHeaders() throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice", PASSWORD);
			String body = changeForm(PASSWORD, NEW_PASSWORD, csrf(get(client, "/api/csrf", session)));
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/me/password"))
					.timeout(Duration.ofSeconds(20)).header("Cookie", session)
					.header("Content-Type", "application/x-www-form-urlencoded")
					.header("currentPassword", "incorrect-header-password").header("newPassword", "short")
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
			assertThat(this.passwords.matches(NEW_PASSWORD, hash(alice.id()))).isTrue();
			assertThat(version(alice.id())).isEqualTo(2);
			assertThat(sessionCount(alice.id())).isZero();
			assertThat(count("password_changed")).isEqualTo(1);
			assertThat(count("browser_sessions_revoked")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "wrong", "Seven amber lanterns by the Café", "bad\ud800" })
	void rejectsWrongCurrentPasswordsWithoutChangingCredentialsOrSessions(String currentPassword) throws Exception {
		var alice = activeUser("alice");
		String hash = hash(alice.id());
		try (var client = client()) {
			String session = login(client, "alice", PASSWORD);
			var page = get(client, "/api/csrf", session);
			String body = "newPassword=" + encode(NEW_PASSWORD) + "&_csrf=" + encode(csrf(page));
			if (currentPassword != null) { body += "&currentPassword=" + encode(currentPassword); }
			var rejected = post(client, "/api/me/password", session, body);
			assertThat(rejected.statusCode()).isEqualTo(400);
			assertThat(rejected.body()).isEqualTo("Password change rejected");
			assertSecurityHeaders(rejected);
			assertThat(rejected.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(hash(alice.id())).isEqualTo(hash);
			assertThat(version(alice.id())).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(count("password_change_failed")).isEqualTo(1);
			assertThat(count("password_changed")).isZero();
			assertThat(this.jdbc.sql("SELECT failures FROM iam_password_authentication_limit ORDER BY dimension").query(Integer.class).list())
					.containsExactly(1, 1);
		}
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "short", "passwordpassword", " Seven amber lanterns by the Cafe\u0301 " })
	void rejectsInvalidOrUnchangedNewPasswordsWithoutLosingTheSession(String newPassword) throws Exception {
		var alice = activeUser("alice");
		String hash = hash(alice.id());
		try (var client = client()) {
			String session = login(client, "alice", PASSWORD);
			String body = "currentPassword=" + encode(PASSWORD) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session)));
			if (newPassword != null) { body += "&newPassword=" + encode(newPassword); }
			assertThat(post(client, "/api/me/password", session, body).statusCode()).isEqualTo(400);
			assertThat(hash(alice.id())).isEqualTo(hash);
			assertThat(version(alice.id())).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(count("password_change_failed")).isEqualTo(1);
			assertThat(count("browser_sessions_revoked")).isZero();
			assertThat(this.jdbc.sql("SELECT failures FROM iam_password_authentication_limit").query(Integer.class).list())
					.allSatisfy(failures -> assertThat(failures).isZero());
		}
	}

	@Test
	void requiresAuthenticationAndCsrfAndRejectsQueryDuplicateAndUnsupportedBodies() throws Exception {
		var alice = activeUser("alice");
		String hash = hash(alice.id());
		try (var client = client()) {
			var anonymous = get(client, "/api/csrf", null);
			assertThat(post(client, "/api/me/password", cookie(anonymous), changeForm(PASSWORD, NEW_PASSWORD, csrf(anonymous)))
					.statusCode()).isEqualTo(401);
			String session = login(client, "alice", PASSWORD);
			String valid = changeForm(PASSWORD, NEW_PASSWORD, csrf(get(client, "/api/csrf", session)));
			assertThat(post(client, "/api/me/password", session, "currentPassword=x&newPassword=y").statusCode()).isEqualTo(403);
			assertThat(post(client, "/api/me/password", session, changeForm(PASSWORD, NEW_PASSWORD, csrf(anonymous))).statusCode()).isEqualTo(403);
			assertThat(get(client, "/api/me/password", session).statusCode()).isEqualTo(403);
			assertThat(post(client, "/api/me/password?userId=" + alice.id(), session, valid).statusCode()).isEqualTo(400);
			assertThat(post(client, "/api/me/password", session, valid + "&newPassword=duplicate").statusCode()).isEqualTo(400);
			assertThat(post(client, "/api/me/password", session, valid + "&padding=" + "x".repeat(8192)).statusCode()).isEqualTo(413);
			var unsupported = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/me/password"))
					.header("Cookie", session).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}"));
			assertThat(client.send(unsupported.build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			var chunked = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/me/password"))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(
							(valid + "&padding=" + "x".repeat(8192)).getBytes(java.nio.charset.StandardCharsets.UTF_8))));
			assertThat(client.send(chunked.build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			assertThat(hash(alice.id())).isEqualTo(hash);
			assertThat(version(alice.id())).isEqualTo(1);
			assertThat(count("password_changed")).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "account", "source" })
	void sharesLoginVerificationBudgetsAndDoesNotHashWhenThrottled(String dimension) throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice", PASSWORD);
			String token = csrf(get(client, "/api/csrf", session));
			if (dimension.equals("account")) {
				for (int i = 0; i < 10; i++) {
					assertThat(post(client, "/api/me/password", session, changeForm("wrong", NEW_PASSWORD, token)).statusCode()).isEqualTo(400);
				}
			}
			else { this.jdbc.sql("UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'").update(); }
			clearInvocations(this.passwords);
			var denied = post(client, "/api/me/password", session, changeForm(PASSWORD, NEW_PASSWORD, token));
			assertThat(denied.statusCode()).isEqualTo(429);
			assertSecurityHeaders(denied);
			verify(this.passwords, never()).matches(any(), any());
			verify(this.passwords, never()).hash(any(), any());
			assertThat(count("password_change_throttled")).isEqualTo(1);
			var login = get(client, "/api/csrf", null);
			assertThat(post(client, "/login", cookie(login), credentials("alice", PASSWORD, csrf(login))).statusCode()).isEqualTo(401);
			assertThat(count("password_auth_throttled")).isEqualTo(1);
			assertThat(version(alice.id())).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			this.jdbc.sql("UPDATE iam_password_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '1 hour'").update();
			assertThat(post(client, "/api/me/password", session, changeForm(PASSWORD, NEW_PASSWORD, token)).statusCode()).isEqualTo(204);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "silent-password", "retained-hash", "retained-version", "sessions", "partial-sessions", "counter",
			"audit", "silent-audit", "deferred-audit", "revoke-audit" })
	void storageAndAuditFaultsRollBackThePasswordVersionAndAllSessionRevocations(String fault) throws Exception {
		var alice = activeUser("alice");
		String original = hash(alice.id());
		try (var client = client()) {
			String first = login(client, "alice", PASSWORD);
			String second = login(client, "alice", PASSWORD);
			String body = changeForm(PASSWORD, NEW_PASSWORD, csrf(get(client, "/api/csrf", first)));
			String table = installFault(fault);
			try {
				var failed = post(client, "/api/me/password", first, body);
				assertThat(failed.statusCode()).isEqualTo(503);
				assertSecurityHeaders(failed);
				assertThat(failed.body()).contains("SERVICE_UNAVAILABLE");
				assertThat(failed.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(failed.headers().firstValue("Location")).isEmpty();
				assertThat(hash(alice.id())).isEqualTo(original);
				assertThat(version(alice.id())).isEqualTo(1);
				assertThat(sessionCount(alice.id())).isEqualTo(2);
				assertThat(count("password_changed")).isZero();
				assertThat(count("browser_sessions_revoked")).isZero();
			}
			finally { removeFault(table); }
			assertThat(get(client, "/api/me", first).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/me", second).statusCode()).isEqualTo(200);
			assertThat(post(client, "/api/me/password", first, body).statusCode()).isEqualTo(204);
		}
	}

	@Test
	void failureAuditFaultRollsBackVerificationCountersAndDoesNotLeakCredentials() throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice", PASSWORD);
			String body = changeForm("wrong", NEW_PASSWORD, csrf(get(client, "/api/csrf", session)));
			String table = installFault("failure-audit");
			try {
				var failed = post(client, "/api/me/password", session, body);
				assertThat(failed.statusCode()).isEqualTo(503);
				assertThat(failed.body()).contains("SERVICE_UNAVAILABLE");
				assertThat(count("password_change_failed")).isZero();
				assertThat(this.jdbc.sql("SELECT failures FROM iam_password_authentication_limit").query(Integer.class).list())
						.allSatisfy(failures -> assertThat(failures).isZero());
				assertThat(version(alice.id())).isEqualTo(1);
			}
			finally { removeFault(table); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void anOldPasswordVerifiedBeforeTheChangeCannotCreateASessionAfterIt() throws Exception {
		var alice = activeUser("alice");
		var verified = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String current = login(client, "alice", PASSWORD);
			String body = changeForm(PASSWORD, NEW_PASSWORD, csrf(get(client, "/api/csrf", current)));
			var page = get(client, "/api/csrf", null);
			doAnswer(call -> {
				Object result = call.callRealMethod();
				verified.countDown();
				assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
				return result;
			}).when(this.authentications).authenticate(eq("alice"), eq(PASSWORD), any());
			var pending = executor.submit(() -> post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page))));
			try {
				assertThat(verified.await(10, TimeUnit.SECONDS)).isTrue();
				assertThat(post(client, "/api/me/password", current, body).statusCode()).isEqualTo(204);
			}
			finally { release.countDown(); }
			var denied = pending.get(10, TimeUnit.SECONDS);
			assertThat(denied.statusCode()).isEqualTo(503);
			assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(denied.headers().firstValue("Location")).isEmpty();
			assertThat(sessionCount(alice.id())).isZero();
			assertThat(count("browser_session_created")).isEqualTo(1);
			assertThat(get(client, "/api/me", cookie(page)).statusCode()).isEqualTo(401);
			assertThat(login(client, "alice", NEW_PASSWORD)).startsWith("__Host-IAMSESSION=");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "/api/me", "/api/me/password" })
	void anAlreadyLoadedRequestCannotRestoreRevokedAuthenticationOrRepeatTheChange(String path) throws Exception {
		var alice = activeUser("alice");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice", PASSWORD);
			Session stale = this.repository.findById(session.split("=", 2)[1]);
			String body = changeForm(PASSWORD, NEW_PASSWORD, csrf(get(client, "/api/csrf", session)));
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path))
					.timeout(Duration.ofSeconds(20)).header("Cookie", session).header("X-Test-Pause", "true");
			if (path.endsWith("password")) {
				request.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body));
			}
			else { request.GET(); }
			var pending = executor.submit(() -> client.send(request.build(), HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				assertThat(post(client, "/api/me/password", session, body).statusCode()).isEqualTo(204);
			}
			finally { this.pause.release.countDown(); }
			var denied = pending.get(10, TimeUnit.SECONDS);
			assertThat(denied.statusCode()).isEqualTo(path.endsWith("password") ? 401 : 503);
			assertThat(denied.body()).doesNotContain(alice.id().toString(), "Alice", NEW_PASSWORD);
			assertThat(version(alice.id())).isEqualTo(2);
			assertThat(sessionCount(alice.id())).isZero();
			assertThat(count("password_changed")).isEqualTo(1);
			assertThatThrownBy(() -> save(stale)).isInstanceOf(IllegalStateException.class);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute" })
	void expiryDuringPasswordHashingRecordsSystemInvalidationInsteadOfUserLogout(String deadlineType) throws Exception {
		var alice = activeUser("alice");
		String originalHash = hash(alice.id());
		try (var client = client()) {
			String other = login(client, "alice", PASSWORD);
			String current = login(client, "alice", PASSWORD);
			String token = csrf(get(client, "/api/csrf", current));
			String sessionId = current.split("=", 2)[1];
			long deadline = System.currentTimeMillis() + 3000;
			if (deadlineType.equals("idle")) {
				this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry WHERE session_id = :id")
						.param("expiry", deadline).param("id", sessionId).update();
			}
			else {
				Session session = this.repository.findById(sessionId);
				session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, deadline - Duration.ofHours(8).toMillis());
				save(session);
			}
			doAnswer(call -> {
				Object hash = call.callRealMethod();
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				return hash;
			}).when(this.passwords).hash(eq(NEW_PASSWORD), eq("alice"));
			var rejected = post(client, "/api/me/password", current, changeForm(PASSWORD, NEW_PASSWORD, token));
			assertThat(rejected.statusCode()).isEqualTo(401);
			assertSecurityHeaders(rejected);
			assertThat(rejected.body()).isEmpty();
			assertThat(rejected.headers().allValues("Set-Cookie")).anySatisfy(value ->
					assertThat(value).contains("__Host-IAMSESSION=", "Max-Age=0", "Secure", "HttpOnly"));
			verify(this.passwords).hash(NEW_PASSWORD, "alice");
			assertThat(hash(alice.id())).isEqualTo(originalHash);
			assertThat(version(alice.id())).isEqualTo(1);
			assertThat(this.repository.findById(sessionId)).isNull();
			assertThat(get(client, "/api/me", current).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", other).statusCode()).isEqualTo(200);
			assertThat(sessionCount(alice.id())).isEqualTo(1);
			assertThat(count("password_changed")).isZero();
			assertThat(count("browser_sessions_revoked")).isZero();
			var failure = this.jdbc.sql("SELECT actor, source, target_user_id FROM iam_security_audit WHERE action = 'password_change_failed'")
					.query().singleRow();
			assertThat(failure.get("actor")).isEqualTo("user:" + alice.id());
			assertThat(failure.get("source")).isEqualTo("browser:password-change");
			assertThat(failure.get("target_user_id")).isEqualTo(alice.id());
			var ended = this.jdbc.sql("SELECT actor, source, target_user_id FROM iam_security_audit WHERE action = 'browser_session_ended'")
					.query().singleRow();
			assertThat(ended.get("actor")).isEqualTo("system:browser-session");
			assertThat(ended.get("source")).isEqualTo("browser:session");
			assertThat(ended.get("target_user_id")).isEqualTo(alice.id());
		}
	}

	private IdentityUser activeUser(String name) {
		var user = this.users.create(name, "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(user.id()).orElseThrow();
	}

	private String login(java.net.http.HttpClient client, String username, String password) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(username, password, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		assertThat(response.headers().firstValue("Location")).isEmpty();
		return cookie(response);
	}

	private static String changeForm(String current, String replacement, String token) {
		return "currentPassword=" + encode(current) + "&newPassword=" + encode(replacement) + "&_csrf=" + encode(token);
	}

	private String hash(UUID userId) {
		return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", userId).query(String.class).single();
	}

	private long version(UUID userId) {
		return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", userId).query(Long.class).single();
	}

	private long sessionCount(UUID userId) {
		return this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :principal")
				.param("principal", userId.toString()).query(Long.class).single();
	}

	private long count(String action) {
		return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action").param("action", action).query(Long.class).single();
	}

	@SuppressWarnings("unchecked")
	private void save(Session session) { ((SessionRepository<Session>) this.repository).save(session); }

	private String installFault(String fault) {
		boolean password = fault.contains("password") || fault.startsWith("retained");
		boolean sessions = fault.contains("sessions");
		boolean counter = fault.equals("counter");
		String table = password ? "iam_password" : sessions ? "iam_browser_session"
				: counter ? "iam_password_authentication_limit" : "iam_security_audit";
		String operation = password || counter ? "UPDATE" : sessions ? "DELETE" : "INSERT";
		String trigger = fault.equals("deferred-audit") ? "CREATE CONSTRAINT TRIGGER password_change_test_fault AFTER "
				: "CREATE TRIGGER password_change_test_fault BEFORE ";
		String deferral = fault.equals("deferred-audit") ? " DEFERRABLE INITIALLY DEFERRED" : "";
		String body;
		if (counter) { body = "RETURN NULL;"; }
		else if (password) {
			body = switch (fault) {
				case "silent-password" -> "RETURN NULL;";
				case "retained-hash" -> "NEW.password_hash := OLD.password_hash; RETURN NEW;";
				case "retained-version" -> "NEW.credential_version := OLD.credential_version; RETURN NEW;";
				default -> "RAISE EXCEPTION 'injected password storage failure';";
			};
		}
		else if (sessions) {
			// Leave one row behind after actually deleting another, to prove atomic rollback of partial revocation.
			body = fault.equals("partial-sessions") ? "IF OLD.session_id = (SELECT min(session_id) FROM iam_browser_session) THEN RETURN NULL; END IF; RETURN OLD;"
					: "RAISE EXCEPTION 'injected session revocation failure';";
		}
		else {
			String action = fault.equals("revoke-audit") ? "browser_sessions_revoked"
					: fault.equals("failure-audit") ? "password_change_failed" : "password_changed";
			body = "IF NEW.action <> '" + action + "' THEN RETURN NEW; END IF; "
					+ (fault.equals("silent-audit") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected password audit failure';");
		}
		this.jdbc.sql("CREATE FUNCTION password_change_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql(trigger + operation + " ON " + table + deferral + " FOR EACH ROW EXECUTE FUNCTION password_change_test_fault()").update();
		return table;
	}

	private void removeFault(String table) {
		this.jdbc.sql("DROP TRIGGER IF EXISTS password_change_test_fault ON " + table).update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS password_change_test_fault()").update();
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean
		RequestPause passwordChangeRequestPause() { return new RequestPause(); }

		@Bean
		WebMvcConfigurer passwordChangeRequestInterceptor(RequestPause pause) {
			return new WebMvcConfigurer() {
				@Override
				public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class RequestPause implements HandlerInterceptor {
		private volatile CountDownLatch entered;
		private volatile CountDownLatch release;

		void start() {
			this.entered = new CountDownLatch(1);
			this.release = new CountDownLatch(1);
		}

		@Override
		public boolean preHandle(jakarta.servlet.http.HttpServletRequest request,
				jakarta.servlet.http.HttpServletResponse response, Object handler) throws Exception {
			if ("true".equals(request.getHeader("X-Test-Pause"))) {
				this.entered.countDown();
				assertThat(this.release.await(10, TimeUnit.SECONDS)).isTrue();
			}
			return true;
		}
	}

}
