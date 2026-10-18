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
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityPasswordRecoveries;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUserStates;
import com.ixayda.iam.service.IdentityUsers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.assertj.core.api.Assertions.*;

// Functional cases share an admission window; the production limit has dedicated boundary tests.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = "iam.browser.requests-per-second=1000")
@Import({ PostgreSqlTestConfiguration.class, IdentityUserStateIntegrationTests.ConcurrentRequests.class })
class IdentityUserStateIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:state-test", "internal:test", UUID.randomUUID());

	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private IdentityUserStates states;
	@Autowired
	private IdentityPasswordRecoveries recoveries;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private RequestPause pause;

	@BeforeEach
	void clean() {
		this.jdbc.sql("DELETE FROM iam_administrator").update();
		this.jdbc.sql("UPDATE iam_admin_bootstrap SET initial_user_id = NULL, completed_at = NULL, revision = 0").update();
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void administratorMembershipDoesNotElevateAnOrdinaryPasswordSessionOrExposeBootstrap() throws Exception {
		var user = activeUser("alice");
		this.jdbc.sql("INSERT INTO iam_administrator (user_id) VALUES (:id)").param("id", user.id()).update();
		try (var client = client()) {
			String session = login(client, "alice");
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			String token = csrf(get(client, "/api/csrf", session));
			for (String path : List.of("/admin", "/admin/bootstrap", "/api/admin", "/api/admin/bootstrap")) {
				assertThat(get(client, path, session).statusCode()).isEqualTo(403);
				assertThat(post(client, path, session, "_csrf=" + encode(token)).statusCode()).isEqualTo(403);
				assertThat(get(client, path, null).statusCode()).isEqualTo(401);
			}
		}
		assertThat(eventCount("admin_bootstrap_completed")).isZero();
	}

	@Test
	void disablingEndsAllOwnedLoginsAndEnablingRequiresANewLoginWithoutAffectingAnotherUser() throws Exception {
		var alice = activeUser("alice");
		activeUser("bobby");
		try (var client = client()) {
			String aliceSession = login(client, "alice");
			String peerSession = login(client, "alice");
			String bobSession = login(client, "bobby");
			String token = csrf(get(client, "/api/csrf", aliceSession));
			for (String path : List.of("/api/me/disable", "/api/users/" + alice.id() + "/disable", "/api/users/" + alice.id() + "/enable")) {
				assertThat(post(client, path, aliceSession, "_csrf=" + encode(token)).statusCode()).isEqualTo(403);
			}
			this.states.disable(alice.id(), SYSTEM);
			assertThat(get(client, "/api/me", aliceSession).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", peerSession).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", bobSession).statusCode()).isEqualTo(200);
			var page = get(client, "/api/csrf", null);
			var denied = post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page)));
			assertThat(denied.statusCode()).isEqualTo(401);
			assertThat(denied.statusCode()).isEqualTo(401);
			assertThatIllegalStateException().isThrownBy(() -> this.recoveries.issue(alice.id(), SYSTEM));
			this.states.enable(alice.id(), SYSTEM);
			assertThat(get(client, "/api/me", aliceSession).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", peerSession).statusCode()).isEqualTo(401);
			String replacement = login(client, "alice");
			var profile = get(client, "/api/me", replacement);
			assertThat(profile.statusCode()).isEqualTo(200);
			assertThat(profile.body()).contains(alice.id().toString(), "Alice").doesNotContain("credentialVersion");
			assertSecurityHeaders(profile);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id")
					.param("id", alice.id().toString()).query(Long.class).single()).isEqualTo(1);
		}
	}

	@Test
	void enablingAPendingAccountDoesNotAllowLoginAndRequiresANewSetupProof() throws Exception {
		var user = this.users.create("alice", "Alice", SYSTEM);
		var oldProof = this.setups.issue(user.id(), SYSTEM);
		this.states.disable(user.id(), SYSTEM);
		this.states.enable(user.id(), SYSTEM);
		assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.PENDING);
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			var denied = post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page)));
			assertThat(denied.statusCode()).isEqualTo(401);
			assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(user.id(), oldProof.token(), PASSWORD, "internal:test", UUID.randomUUID()));
			var proof = this.setups.issue(user.id(), SYSTEM);
			this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
			assertThat(get(client, "/api/me", login(client, "alice")).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void aPasswordVerifiedBeforeDisableCannotEstablishASessionAfterReEnabling() throws Exception {
		var alice = activeUser("alice");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			var page = get(client, "/api/csrf", null);
			this.pause.start("login");
			var pending = executor.submit(() -> post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page))));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).as("Password validated before session persistence").isTrue();
				assertThat(eventCount("password_authenticated")).isEqualTo(1);
				this.states.disable(alice.id(), SYSTEM);
				this.states.enable(alice.id(), SYSTEM);
			}
			finally { this.pause.release.countDown(); }
			var denied = pending.get(10, TimeUnit.SECONDS);
			assertThat(denied.statusCode()).isEqualTo(503);
			assertThat(denied.body()).contains("SERVICE_UNAVAILABLE");
			assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(denied.headers().firstValue("Location")).isEmpty();
			assertSecurityHeaders(denied);
			assertThat(eventCount("browser_session_created")).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id")
					.param("id", alice.id().toString()).query(Long.class).single()).isZero();
			assertThat(get(client, "/api/me", login(client, "alice")).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "profile", "password", "read" })
	void alreadyLoadedRequestsCannotPublishPrivateDataOrChangesAfterDisableAndReEnable(String operation) throws Exception {
		var alice = activeUser("alice");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			String path = operation.equals("read") ? "/api/me" : "/api/me/" + operation;
			String body = operation.equals("password") ? "currentPassword=" + encode(PASSWORD) + "&newPassword=" + encode(NEW_PASSWORD)
					: "displayName=Changed";
			var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20))
					.header("Cookie", session).header("X-Test-State-Pause", "true").header("Content-Type", "application/x-www-form-urlencoded");
			var request = operation.equals("read") ? builder.GET().build()
					: builder.POST(HttpRequest.BodyPublishers.ofString(body + "&_csrf=" + encode(token))).build();
			this.pause.start("request");
			var pending = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).as("Request reached the authenticated controller").isTrue();
				this.states.disable(alice.id(), SYSTEM);
				this.states.enable(alice.id(), SYSTEM);
			}
			finally { this.pause.release.countDown(); }
			var denied = pending.get(10, TimeUnit.SECONDS);
			assertThat(denied.statusCode()).isEqualTo(operation.equals("read") ? 503 : 401);
			assertThat(denied.body()).doesNotContain(alice.id().toString(), "Alice", "Changed", "credential_version");
			assertThat(denied.headers().allValues("Set-Cookie")).noneMatch(value -> !value.contains("Max-Age=0"));
			assertSecurityHeaders(denied);
			assertThat(this.users.findById(alice.id()).orElseThrow().displayName()).isEqualTo("Alice");
			assertThat(eventCount("user_profile_updated")).isZero();
			assertThat(eventCount("password_changed")).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", login(client, "alice")).statusCode()).isEqualTo(200);
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
		assertThat(response.headers().firstValue("Location")).isEmpty();
		return cookie(response);
	}

	private long eventCount(String action) {
		return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action").param("action", action).query(Long.class).single();
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean
		RequestPause stateRequestPause() { return new RequestPause(); }

		@Bean
		ApplicationListener<InteractiveAuthenticationSuccessEvent> stateLoginPause(RequestPause pause) {
			return event -> pause.awaitRelease("login");
		}

		@Bean
		WebMvcConfigurer stateRequestInterceptor(RequestPause pause) {
			return new WebMvcConfigurer() {
				@Override
				public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class RequestPause implements HandlerInterceptor {
		private volatile String point;
		private volatile CountDownLatch entered;
		private volatile CountDownLatch release;

		void start(String point) {
			this.entered = new CountDownLatch(1);
			this.release = new CountDownLatch(1);
			this.point = point;
		}

		void awaitRelease(String point) {
			if (point.equals(this.point)) {
				this.entered.countDown();
				try { assertThat(this.release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}
		}

		@Override
		public boolean preHandle(jakarta.servlet.http.HttpServletRequest request,
				jakarta.servlet.http.HttpServletResponse response, Object handler) {
			if ("true".equals(request.getHeader("X-Test-State-Pause"))) { awaitRelease("request"); }
			return true;
		}
	}

}
