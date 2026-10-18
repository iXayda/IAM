package com.ixayda.iam.security;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityPasswordRecoveries;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.assertj.core.api.Assertions.*;

// Functional cases share one admission window; rate enforcement has dedicated boundary tests.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = "iam.browser.requests-per-second=1000")
@Import({ PostgreSqlTestConfiguration.class, IdentityProfileUpdateIntegrationTests.ConcurrentRequests.class })
class IdentityProfileUpdateIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final String PATH = "/api/me/profile";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:profile-test", "internal:test", UUID.randomUUID());

	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private IdentityPasswordRecoveries recoveries;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private RequestPause pause;

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void updatesOnlyTheCallerAndKeepsBothUsersSessionsUsable() throws Exception {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		try (var client = client()) {
			String aliceSession = login(client, "alice");
			String otherAliceSession = login(client, "alice");
			String bobSession = login(client, "bobby");
			String token = csrf(get(client, "/api/csrf", aliceSession));
			var response = post(client, PATH, aliceSession, updateForm(" Cafe\u0301 用户 ", token));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.body()).isEmpty();
			assertSecurityHeaders(response);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(this.users.findById(alice.id()).orElseThrow().displayName()).isEqualTo(" Café 用户 ");
			assertThat(this.users.findById(bob.id())).contains(bob);
			assertThat(get(client, "/api/me", aliceSession).body()).contains(" Café 用户 ");
			assertThat(get(client, "/api/me", otherAliceSession).body()).contains(" Café 用户 ");
			assertThat(get(client, "/api/me", bobSession).body()).contains("Alice").doesNotContain("Café");
			assertThat(post(client, PATH, aliceSession, updateForm(" Café 用户 ", token)).statusCode()).isEqualTo(204);
			assertThat(profileEvents()).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password").query(Long.class).list()).containsOnly(1L);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isEqualTo(3);
		}
	}

	@Test
	void acceptsTheCurrentCsrfTokenInAHeaderWithoutRequiringAFormToken() throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
					.header("Cookie", session).header("X-CSRF-TOKEN", token).header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString("displayName=" + encode("Header user"))).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
			assertThat(this.users.findById(alice.id()).orElseThrow().displayName()).isEqualTo("Header user");
			assertThat(profileEvents()).isEqualTo(1);
		}
	}

	@Test
	void requiresAuthenticationCsrfAndPostAndRejectsUndeclaredOrAmbiguousFields() throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			var anonymous = get(client, "/api/csrf", null);
			assertThat(post(client, PATH, cookie(anonymous), updateForm("Changed", csrf(anonymous))).statusCode()).isEqualTo(401);
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			assertThat(post(client, PATH, session, "displayName=Changed").statusCode()).isEqualTo(403);
			assertThat(post(client, PATH, session, updateForm("Changed", csrf(anonymous))).statusCode()).isEqualTo(403);
			assertThat(get(client, PATH, session).statusCode()).isEqualTo(403);
			for (String method : List.of("PUT", "PATCH", "DELETE")) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
						.header("Cookie", session).header("X-CSRF-TOKEN", token)
						.method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
			}
			String valid = updateForm("Changed", token);
			assertThat(post(client, PATH + "?displayName=Query", session, valid).statusCode()).isEqualTo(400);
			for (String extra : List.of("displayName=Again", "_csrf=Again", "userId=" + UUID.randomUUID(),
					"username=admin", "status=active", "actor=system:admin", "displayName.value=Changed")) {
				assertThat(post(client, PATH, session, valid + "&" + extra).statusCode()).as(extra).isEqualTo(400);
			}
			for (String body : List.of("_csrf=" + encode(token), updateForm("", token), updateForm(" \u3000", token),
					updateForm("Changed\n", token), updateForm("😀".repeat(129), token))) {
				var response = post(client, PATH, session, body);
				assertThat(response.statusCode()).isEqualTo(400);
				assertThat(response.body()).isEqualTo("Profile update rejected");
				assertSecurityHeaders(response);
			}
			assertThat(this.users.findById(alice.id())).contains(alice);
			assertThat(profileEvents()).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "single", "duplicate", "hyphenated" })
	void neverUsesRequestHeadersAsProfileFields(String variant) throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			String header = variant.equals("hyphenated") ? "Display-Name" : "displayName";
			for (String body : List.of("_csrf=" + encode(token), updateForm("", token))) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
						.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
						.header(header, "HeaderOnlyName").POST(HttpRequest.BodyPublishers.ofString(body));
				if (variant.equals("duplicate")) { request.header(header, "AnotherHeaderName"); }
				var response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
				assertThat(response.statusCode()).isEqualTo(400);
				assertThat(response.body()).isEqualTo("Profile update rejected");
				assertSecurityHeaders(response);
				assertThat(this.users.findById(alice.id())).contains(alice);
				assertThat(profileEvents()).isZero();
			}
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header(header, "HeaderOnlyName").POST(HttpRequest.BodyPublishers.ofString(updateForm("Form name", token)));
			if (variant.equals("duplicate")) { request.header(header, "AnotherHeaderName"); }
			assertThat(client.send(request.build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(204);
			assertThat(this.users.findById(alice.id()).orElseThrow().displayName()).isEqualTo("Form name");
			assertThat(profileEvents()).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void boundsKnownAndChunkedBodiesAndRequiresFormEncoding() throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			String large = updateForm("x".repeat(8192), token);
			assertThat(post(client, PATH, session, large).statusCode()).isEqualTo(413);
			var chunked = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(large.getBytes(StandardCharsets.UTF_8))));
			assertThat(client.send(chunked.build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			for (String type : List.of("application/json", "text/plain")) {
				var unsupported = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
						.header("Cookie", session).header("Content-Type", type).POST(HttpRequest.BodyPublishers.ofString("{}"));
				assertThat(client.send(unsupported.build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			}
			assertThat(this.users.findById(alice.id())).contains(alice);
			assertThat(profileEvents()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "storage", "silent-storage", "retained-name", "audit", "silent-audit", "deferred-audit" })
	void storageAndAuditFaultsRollBackTheUpdateAndNeverPublishSuccess(String fault) throws Exception {
		var alice = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String body = updateForm("Private new name", csrf(get(client, "/api/csrf", session)));
			String table = installFault(fault);
			try {
				var failed = post(client, PATH, session, body);
				assertThat(failed.statusCode()).isEqualTo(503);
				assertThat(failed.body()).contains("SERVICE_UNAVAILABLE");
				assertSecurityHeaders(failed);
				assertThat(failed.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(this.users.findById(alice.id())).contains(alice);
				assertThat(profileEvents()).isZero();
			}
			finally { removeFault(table); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(post(client, PATH, session, body).statusCode()).isEqualTo(204);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password-change", "recovery", "logout" })
	void anAlreadyAuthenticatedRequestCannotUpdateAfterItsSessionIsRevoked(String operation) throws Exception {
		var alice = activeUser("alice");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH)).timeout(Duration.ofSeconds(20))
					.header("Cookie", session).header("X-Test-Pause", "true").header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString(updateForm("Changed", token))).build();
			var pending = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS))
						.as("Profile request reached the controller; early HTTP response: %s",
								pending.isDone() ? pending.get(1, TimeUnit.SECONDS).statusCode() : "pending").isTrue();
				if (operation.equals("password-change")) {
					assertThat(post(client, "/api/me/password", session, "currentPassword=" + encode(PASSWORD)
							+ "&newPassword=" + encode(NEW_PASSWORD) + "&_csrf=" + encode(token)).statusCode()).isEqualTo(204);
				}
				else if (operation.equals("recovery")) {
					var proof = this.recoveries.issue(alice.id(), SYSTEM);
					assertThat(this.recoveries.complete(alice.id(), proof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID()))
							.isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
				}
				else { assertThat(post(client, "/logout", session, "_csrf=" + encode(token)).statusCode()).isEqualTo(204); }
			}
			finally { this.pause.release.countDown(); }
			var denied = pending.get(10, TimeUnit.SECONDS);
			assertThat(denied.statusCode()).isEqualTo(401);
			assertThat(denied.body()).isEmpty();
			assertSecurityHeaders(denied);
			assertThat(this.users.findById(alice.id()).orElseThrow().displayName()).isEqualTo("Alice");
			assertThat(profileEvents()).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
		}
	}

	private IdentityUser activeUser(String name) {
		var user = this.users.create(name, "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(user.id()).orElseThrow();
	}

	private String login(java.net.http.HttpClient client, String username) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(username, PASSWORD, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}

	private static String updateForm(String displayName, String token) {
		return "displayName=" + encode(displayName) + "&_csrf=" + encode(token);
	}

	private long profileEvents() {
		return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'user_profile_updated'").query(Long.class).single();
	}

	private String installFault(String fault) {
		boolean storage = fault.contains("storage") || fault.equals("retained-name");
		String table = storage ? "iam_user" : "iam_security_audit";
		String body = storage ? switch (fault) {
			case "silent-storage" -> "RETURN NULL;";
			case "retained-name" -> "NEW.display_name := OLD.display_name; RETURN NEW;";
			default -> "RAISE EXCEPTION 'injected profile storage failure';";
		} : "IF NEW.action <> 'user_profile_updated' THEN RETURN NEW; END IF; "
				+ (fault.equals("silent-audit") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected profile audit failure';");
		this.jdbc.sql("CREATE FUNCTION profile_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		String trigger = fault.equals("deferred-audit") ? "CREATE CONSTRAINT TRIGGER profile_test_fault AFTER INSERT ON " + table
				+ " DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER profile_test_fault BEFORE " + (storage ? "UPDATE" : "INSERT") + " ON " + table;
		this.jdbc.sql(trigger + " FOR EACH ROW EXECUTE FUNCTION profile_test_fault()").update();
		return table;
	}

	private void removeFault(String table) {
		this.jdbc.sql("DROP TRIGGER IF EXISTS profile_test_fault ON " + table).update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS profile_test_fault()").update();
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean
		RequestPause profileRequestPause() { return new RequestPause(); }

		@Bean
		WebMvcConfigurer profileRequestInterceptor(RequestPause pause) {
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
