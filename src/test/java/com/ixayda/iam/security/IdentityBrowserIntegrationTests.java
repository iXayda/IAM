package com.ixayda.iam.security;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
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

/** Real TLS requests and PostgreSQL, including the response/session commit boundary. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "iam.browser.requests-per-second=1000")
@Import({ PostgreSqlTestConfiguration.class, IdentityBrowserIntegrationTests.ConcurrentRequests.class })
class IdentityBrowserIntegrationTests {

	private static final String PASSWORD = " Seven amber lanterns by the Café ";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:browser-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_STORE = createKeyStore();

	@LocalServerPort
	private int port;

	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private SessionRepository<?> repository;
	@Autowired
	private PostgreSQLContainer postgres;
	@Autowired
	private ProfileRequestPause profilePause;
	@Autowired
	private CsrfRequestPause csrfPause;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry properties) {
		properties.add("server.ssl.enabled", () -> true);
		properties.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		properties.add("server.ssl.key-store-password", () -> "test-store-password");
		properties.add("iam.password-authentication.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void loginRotatesTheSessionAndLogoutRevokesIt() throws Exception {
		IdentityUser user = activeUser("alice");
		try (HttpClient client = client()) {
			var unauthenticated = get(client, "/api/me", null);
			assertThat(unauthenticated.statusCode()).isEqualTo(401);
			assertSecurityHeaders(unauthenticated);
			var page = get(client, "/api/csrf", null);
			assertThat(page.statusCode()).isEqualTo(200);
			assertThat(page.headers().firstValue("Cache-Control")).contains("no-store");
			String anonymous = cookie(page);
			assertThat(page.headers().firstValue("Set-Cookie").orElseThrow())
					.contains("Secure", "HttpOnly", "Path=/", "SameSite=Lax").doesNotContain("Domain=");
			assertThat(anonymous).startsWith("__Host-IAMSESSION=");
			var login = post(client, "/login", anonymous, credentials("alice", PASSWORD, csrf(page)));
			assertThat(login.statusCode()).isEqualTo(204);
			assertThat(login.headers().firstValue("Location")).isEmpty();
			String authenticated = cookie(login);
			assertThat(authenticated).isNotEqualTo(anonymous);
			Session stored = this.repository.findById(sessionId(authenticated));
			assertThat(stored.getAttributeNames()).contains("org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN");
			var profile = get(client, "/api/me", authenticated);
			assertThat(profile.statusCode()).isEqualTo(200);
			assertThat(profile.body()).contains(user.id().toString(), "alice", "Private Display")
					.doesNotContain("password", "authorities", "status");
			assertThat(get(client, "/api/me", anonymous).statusCode()).isEqualTo(401);
			assertThat(count("browser_session_created")).isEqualTo(1);
			var csrfResponse = get(client, "/api/csrf", authenticated);
			assertThat(csrfResponse.statusCode()).isEqualTo(200);
			var logout = post(client, "/logout", authenticated, withCsrf(csrf(csrfResponse)));
			assertThat(logout.statusCode()).isEqualTo(204);
			assertThat(logout.headers().allValues("Set-Cookie")).anySatisfy(value -> assertThat(value).contains("Max-Age=0"));
			assertThat(get(client, "/api/me", authenticated).statusCode()).isEqualTo(401);
			assertThat(count("browser_session_ended")).isEqualTo(1);
			var event = this.jdbc.sql("SELECT actor, source FROM iam_security_audit WHERE action = 'browser_session_ended'").query().singleRow();
			assertThat(event.get("actor")).isEqualTo("user:" + user.id());
			assertThat(event.get("source")).isEqualTo("browser:logout");
		}
	}

	@Test
	void csrfIsRequiredForLoginAndLogoutAndGetLogoutDoesNotMutate() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			String anonymous = cookie(page);
			assertThat(post(client, "/login", anonymous, "{\"username\":\"alice\",\"password\":\"ignored\"}").statusCode()).isEqualTo(403);
			assertThat(post(client, "/login", anonymous, credentials("alice", PASSWORD, "invalid")).statusCode()).isEqualTo(403);
			assertThat(count("password_authenticated")).isZero();
			String session = cookie(post(client, "/login", anonymous, credentials("alice", PASSWORD, csrf(page))));
			var noCsrf = post(client, "/logout", session, "");
			assertThat(noCsrf.statusCode()).isEqualTo(403);
			assertSecurityHeaders(noCsrf);
			assertThat(post(client, "/logout", session, withCsrf(csrf(page))).statusCode()).isEqualTo(403);
			assertThat(get(client, "/logout", session).statusCode()).isEqualTo(403);
			assertThat(get(client, "/api/csrf", session).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(count("browser_session_ended")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "unknown", "wrong", "pending", "disabled" })
	void credentialDenialsHaveTheSamePublicResponse(String mode) throws Exception {
		var user = mode.equals("pending") ? this.users.create("alice", "Private Display", SYSTEM) : activeUser("alice");
		if (mode.equals("disabled")) {
			this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", user.id()).update();
		}
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			var denied = post(client, "/login", cookie(page), credentials(mode.equals("unknown") ? "unknown" : "alice",
					mode.equals("wrong") ? "wrong" : PASSWORD, csrf(page)));
			assertThat(denied.statusCode()).isEqualTo(401);
			assertThat(denied.headers().firstValue("Location")).isEmpty();
			assertError(denied, "INVALID_CREDENTIALS");
			assertThat(denied.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(get(client, "/api/me", cookie(page)).statusCode()).isEqualTo(401);
			assertThat(count("browser_session_created")).isZero();
			assertThat(count("password_auth_failed")).isEqualTo(1);
			var bytes = this.jdbc.sql("SELECT attribute_bytes FROM iam_browser_session_attributes").query(byte[].class).list();
			for (byte[] value : bytes) {
				assertThat(new String(value, StandardCharsets.ISO_8859_1)).doesNotContain("BadCredentials", "wrong", PASSWORD);
			}
		}
	}

	@Test
	void authenticationDependencyFailureRecordsDiagnosticsWithoutPublishingSecretsOrSuccess() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			installFault("audit", "iam_security_audit", "password_authenticated", false);
			try (var diagnostics = new IdentityBrowserLogCapture()) {
				var response = post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page)));
				assertThat(response.statusCode()).isEqualTo(503);
				assertError(response, "AUTHENTICATION_UNAVAILABLE");
				assertSecurityHeaders(response);
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(response.headers().firstValue("Location")).isEmpty();
				assertThat(diagnostics.events()).singleElement().satisfies(event -> {
					assertThat(event.getMessage().getFormattedMessage()).contains("event=browser_failure", "stage=AUTHENTICATION",
							"causeType=org.postgresql.util.PSQLException", "sqlState=P0001")
							.doesNotContain(PASSWORD, cookie(page), csrf(page), "injected session failure");
					assertThat(event.getThrown()).isNull();
				});
				assertThat(count("password_authenticated")).isZero();
				assertThat(count("browser_session_created")).isZero();
			}
			finally {
				removeFault("iam_security_audit");
			}
		}
	}

	@Test
	void profileIsBoundToTheAuthenticatedIdentityAndDoesNotGrantAdministrativeAccess() throws Exception {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		try (var client = client()) {
			String session = login(client);
			var own = get(client, "/api/me?id=" + bob.id(), session);
			assertThat(own.statusCode()).isEqualTo(200);
			assertThat(own.body()).contains(alice.id().toString()).doesNotContain(bob.id().toString(), "bobby");
			assertThat(get(client, "/api/users", session).statusCode()).isEqualTo(403);
			assertThat(get(client, "/admin", session).statusCode()).isEqualTo(403);
			assertThat(post(client, "/api/me", session, "").statusCode()).isEqualTo(403);
		}
	}

	@Test
	void storedAuthenticationContainsOnlyIdentityAndNoTransportDetailsOrCredentials() throws Exception {
		var user = activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			Session stored = this.repository.findById(sessionId(session));
			SecurityContext context = stored.getAttribute("SPRING_SECURITY_CONTEXT");
			assertThat(context.getAuthentication().getPrincipal()).isEqualTo(user.id());
			assertThat(context.getAuthentication().getCredentials()).isNull();
			assertThat(context.getAuthentication().getDetails()).isNull();
			assertThat(context.getAuthentication().getAuthorities()).isEmpty();
			assertThat(stored.getAttributeNames()).doesNotContain("iam.loginPending", "iam.originalSessionId", "SPRING_SECURITY_LAST_EXCEPTION");
			for (byte[] bytes : this.jdbc.sql("SELECT attribute_bytes FROM iam_browser_session_attributes").query(byte[].class).list()) {
				assertThat(new String(bytes, StandardCharsets.UTF_8)).doesNotContain(PASSWORD, "127.0.0.1", "PasswordAuthenticationContext", "Private Display");
			}
			var events = this.jdbc.sql("SELECT action, correlation_id FROM iam_security_audit WHERE action IN ('password_authenticated', 'browser_session_created')")
					.query().listOfRows();
			assertThat(events).hasSize(2);
			assertThat(events.get(0).get("correlation_id")).isEqualTo(events.get(1).get("correlation_id"));
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute", "missing-time", "future-time", "overflow-time", "disabled", "missing-version", "stale-version", "malformed-version" })
	void expiryAndAccountStatusRejectPersistedAuthentication(String mode) throws Exception {
		var user = activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			if (mode.equals("idle")) {
				this.jdbc.sql("UPDATE iam_browser_session SET last_access_time = 1, expiry_time = 1").update();
			}
			else if (mode.equals("disabled")) {
				this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", user.id()).update();
			}
			else if (mode.equals("missing-time")) {
				this.jdbc.sql("DELETE FROM iam_browser_session_attributes WHERE attribute_name = 'iam.authenticatedAt'").update();
			}
			else if (mode.equals("missing-version")) {
				this.jdbc.sql("DELETE FROM iam_browser_session_attributes WHERE attribute_name = 'iam.credentialVersion'").update();
			}
			else if (mode.endsWith("version")) {
				Object version = mode.equals("stale-version") ? 2L : "1";
				this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes = :bytes WHERE attribute_name = 'iam.credentialVersion'")
						.param("bytes", SerializationUtils.serialize(version)).update();
			}
			else {
				long time = switch (mode) {
					case "future-time" -> System.currentTimeMillis() + 3_600_000;
					case "overflow-time" -> Long.MIN_VALUE;
					default -> System.currentTimeMillis() - 28_800_001;
				};
				this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes = :bytes WHERE attribute_name = 'iam.authenticatedAt'")
						.param("bytes", SerializationUtils.serialize(time)).update();
			}
			var rejected = get(client, "/api/me", session);
			assertThat(rejected.statusCode()).isEqualTo(401);
			assertSecurityHeaders(rejected);
			if (!mode.equals("idle")) {
				assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'browser_session_ended'").query(String.class).single())
						.isEqualTo("system:browser-session");
			}
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE session_id = :id")
					.param("id", sessionId(session)).query(Long.class).single()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "session", "audit", "deferred-audit", "silent-session", "silent-attributes", "silent-csrf", "silent-version" })
	void loginStorageOrAuditFailureCannotPublishSuccessAndRollsBackSession(String mode) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			String anonymous = cookie(page);
			String table = mode.contains("audit") ? "iam_security_audit" : (mode.equals("silent-attributes") || mode.equals("silent-csrf") || mode.equals("silent-version")) ? "iam_browser_session_attributes" : "iam_browser_session";
			installFault(mode, table, "browser_session_created", false);
			try {
				var response = post(client, "/login", anonymous, credentials("alice", PASSWORD, csrf(page)));
				assertThat(response.statusCode()).isEqualTo(503);
				assertSecurityHeaders(response);
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(response.headers().firstValue("Location")).isEmpty();
				assertError(response, "SERVICE_UNAVAILABLE");
				assertThat(count("browser_session_created")).isZero();
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name IS NOT NULL").query(Long.class).single()).isZero();
			}
			finally { removeFault(table); }
			assertThat(get(client, "/api/me", anonymous).statusCode()).isEqualTo(401);
			assertThat(count("password_authenticated")).isEqualTo(1);
			assertThat(login(client)).isNotEqualTo(anonymous);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "session", "audit", "deferred-audit", "silent-session" })
	void logoutStorageOrAuditFailureKeepsTheSessionAndCannotPublishSuccess(String mode) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			var page = get(client, "/api/csrf", session);
			String table = mode.contains("audit") ? "iam_security_audit" : "iam_browser_session";
			installFault(mode, table, "browser_session_ended", true);
			try {
				var response = post(client, "/logout", session, withCsrf(csrf(page)));
				assertThat(response.statusCode()).isEqualTo(503);
				assertSecurityHeaders(response);
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(count("browser_session_ended")).isZero();
			}
			finally { removeFault(table); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void switchingAccountsPersistsTheNewIdentityAndInvalidatesTheOldId() throws Exception {
		activeUser("alice");
		var bobby = activeUser("bobby");
		try (var client = client()) {
			String original = login(client);
			var page = get(client, "/api/csrf", original);
			var response = post(client, "/login", original, credentials("bobby", PASSWORD, csrf(page)));
			assertThat(response.statusCode()).isEqualTo(204);
			String switched = cookie(response);
			assertThat(switched).isNotEqualTo(original);
			assertThat(get(client, "/api/me", switched).body()).contains(bobby.id().toString(), "bobby");
			assertThat(get(client, "/api/me", original).statusCode()).isEqualTo(401);
			assertThat(count("browser_session_created")).isEqualTo(2);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "context", "time", "csrf" })
	void silentlyIgnoredAttributeChangesRollBackAccountSwitch(String attribute) throws Exception {
		var alice = activeUser("alice");
		activeUser("bobby");
		try (var client = client()) {
			String original = login(client);
			// Ensure a retained authentication timestamp differs from the new login timestamp.
			this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes = :bytes WHERE attribute_name = 'iam.authenticatedAt'")
					.param("bytes", SerializationUtils.serialize(System.currentTimeMillis() - 60_000)).update();
			var page = get(client, "/api/csrf", original);
			String condition = switch (attribute) {
				case "context" -> "NEW.attribute_name = 'SPRING_SECURITY_CONTEXT'";
				case "time" -> "NEW.attribute_name = 'iam.authenticatedAt'";
				default -> "NEW.attribute_name LIKE '%CSRF_TOKEN'";
			};
			this.jdbc.sql("CREATE FUNCTION browser_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF "
					+ condition + " THEN RETURN NULL; END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER browser_test_fault BEFORE UPDATE"
					+ " ON iam_browser_session_attributes FOR EACH ROW EXECUTE FUNCTION browser_test_fault()").update();
			try {
				var response = post(client, "/login", original, credentials("bobby", PASSWORD, csrf(page)));
				assertThat(response.statusCode()).isEqualTo(503);
				assertSecurityHeaders(response);
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(response.headers().firstValue("Location")).isEmpty();
				assertError(response, "SERVICE_UNAVAILABLE");
				assertThat(count("browser_session_created")).isEqualTo(1);
				Session stored = this.repository.findById(sessionId(original));
				assertThat(stored).isNotNull();
				SecurityContext context = stored.getAttribute("SPRING_SECURITY_CONTEXT");
				assertThat(context.getAuthentication().getPrincipal()).isEqualTo(alice.id());
			}
			finally { removeFault("iam_browser_session_attributes"); }
			assertThat(get(client, "/api/me", original).body()).contains(alice.id().toString(), "alice");
			assertThat(count("password_authenticated")).isEqualTo(2);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "last_access_time", "expiry_time" })
	void silentlyRetainedSessionMetadataCannotPublishProfile(String column) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			this.jdbc.sql("UPDATE iam_browser_session SET last_access_time = last_access_time - 60000, expiry_time = expiry_time - 60000").update();
			var before = this.jdbc.sql("SELECT last_access_time, expiry_time FROM iam_browser_session").query().singleRow();
			this.jdbc.sql("CREATE FUNCTION browser_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW."
					+ column + " := OLD." + column + "; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER browser_test_fault BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION browser_test_fault()").update();
			try {
				var response = get(client, "/api/me", session);
				assertThat(response.statusCode()).isEqualTo(503);
				assertSecurityHeaders(response);
				assertError(response, "SERVICE_UNAVAILABLE");
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(this.jdbc.sql("SELECT last_access_time, expiry_time FROM iam_browser_session").query().singleRow()).isEqualTo(before);
			}
			finally { removeFault("iam_browser_session"); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void repeatedAnonymousSaveAfterAConcurrentRequestKeepsTheSessionUsable() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var token = get(client, "/api/csrf", null);
			String anonymous = cookie(token);
			Session first = this.repository.findById(sessionId(anonymous));
			first.setLastAccessedTime(java.time.Instant.now());
			save(first);
			Session concurrent = this.repository.findById(sessionId(anonymous));
			concurrent.setLastAccessedTime(first.getLastAccessedTime().plusMillis(1));
			save(concurrent);
			// Response closure and the filter's finally block can save the same anonymous snapshot twice.
			save(first);
			var fresh = get(client, "/api/csrf", anonymous);
			assertThat(post(client, "/login", anonymous, credentials("alice", PASSWORD, csrf(fresh))).statusCode()).isEqualTo(204);
			assertThat(count("browser_session_created")).isEqualTo(1);
		}
	}

	@Test
	void silentlyDroppedAnonymousCsrfTokenCannotPublishTokenOrCookie() throws Exception {
		installFault("silent-attributes", "iam_browser_session_attributes", "", false);
		try (var client = client()) {
			var response = get(client, "/api/csrf", null);
			assertThat(response.statusCode()).isEqualTo(503);
			assertSecurityHeaders(response);
			assertError(response, "SERVICE_UNAVAILABLE");
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
		}
		finally { removeFault("iam_browser_session_attributes"); }
	}

	@Test
	void silentlyIgnoredCsrfRemovalRollsBackTheSession() throws Exception {
		activeUser("alice");
		String csrfAttribute = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";
		try (var client = client()) {
			String session = login(client);
			Session changed = this.repository.findById(sessionId(session));
			org.springframework.security.web.csrf.CsrfToken original = changed.getAttribute(csrfAttribute);
			changed.removeAttribute(csrfAttribute);
			installFault("silent-attributes", "iam_browser_session_attributes", "", true);
			try { assertThatThrownBy(() -> save(changed)).isInstanceOf(IllegalStateException.class).hasMessageContaining("attribute was not stored"); }
			finally { removeFault("iam_browser_session_attributes"); }
			org.springframework.security.web.csrf.CsrfToken stored = this.repository.findById(sessionId(session)).getAttribute(csrfAttribute);
			assertThat(stored.getToken()).isEqualTo(original.getToken());
			var page = get(client, "/api/csrf", session);
			assertThat(post(client, "/logout", session, withCsrf(csrf(page))).statusCode()).isEqualTo(204);
			assertThat(count("browser_session_created")).isEqualTo(1);
			assertThat(count("browser_session_ended")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "created", "updated", "removed" })
	void concurrentCsrfChangesDoNotFailAnOtherwiseHealthyProfile(String change) throws Exception {
		var alice = activeUser("alice");
		String csrfAttribute = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client);
			if (change.equals("created")) {
				// Exercise concurrent creation on a session without this attribute.
				Session withoutToken = this.repository.findById(sessionId(session));
				withoutToken.removeAttribute(csrfAttribute);
				save(withoutToken);
			}
			var pause = this.profilePause.start();
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/me"))
					.timeout(Duration.ofSeconds(20)).header("Cookie", session).header("X-Test-Pause", "true").GET().build();
			var profile = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (change.equals("created")) {
					assertThat(get(client, "/api/csrf", session).statusCode()).isEqualTo(200);
				}
				else {
					Session concurrent = this.repository.findById(sessionId(session));
					if (change.equals("removed")) { concurrent.removeAttribute(csrfAttribute); }
					else { concurrent.setAttribute(csrfAttribute, new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "replacement-token")); }
					save(concurrent);
				}
			}
			finally { pause.release.countDown(); this.profilePause.active = null; }
			var response = profile.get(10, TimeUnit.SECONDS);
			assertThat(response.statusCode()).isEqualTo(200);
			assertThat(response.body()).contains(alice.id().toString(), "alice");
			assertSecurityHeaders(response);
			Session stored = this.repository.findById(sessionId(session));
			if (change.equals("removed")) {
				assertThat(stored.getAttributeNames()).doesNotContain(csrfAttribute);
			}
			else {
				org.springframework.security.web.csrf.CsrfToken token = stored.getAttribute(csrfAttribute);
				assertThat(token).isNotNull();
				if (change.equals("updated")) { assertThat(token.getToken()).isEqualTo("replacement-token"); }
				else {
					var page = get(client, "/api/csrf", session);
					assertThat(post(client, "/logout", session, withCsrf(csrf(page))).statusCode()).isEqualTo(204);
				}
			}
			assertThat(count("browser_session_created")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "first", "second" })
	void concurrentCsrfRequestsShareTheCommittedTokenAndBothResponsesAreUsable(String selected) throws Exception {
		activeUser("alice");
		String csrfAttribute = "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN";
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client);
			Session initial = this.repository.findById(sessionId(session));
			org.springframework.security.web.csrf.CsrfToken committed = initial.getAttribute(csrfAttribute);
			assertThat(committed).isNotNull();
			var pause = this.csrfPause.start();
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/csrf"))
					.timeout(Duration.ofSeconds(20)).header("Cookie", session).header("X-Test-Pause", "true").GET().build();
			var first = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			HttpResponse<String> second;
			try {
				assertThat(pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				second = get(client, "/api/csrf", session);
				assertThat(second.statusCode()).isEqualTo(200);
			}
			finally { pause.release.countDown(); this.csrfPause.active = null; }
			var firstPage = first.get(10, TimeUnit.SECONDS);
			assertThat(firstPage.statusCode()).isEqualTo(200);
			assertSecurityHeaders(firstPage);
			assertSecurityHeaders(second);
			org.springframework.security.web.csrf.CsrfToken stored = this.repository.findById(sessionId(session)).getAttribute(csrfAttribute);
			assertThat(stored.getToken()).isEqualTo(committed.getToken());
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(count("browser_session_created")).isEqualTo(1);
			assertThat(count("browser_session_ended")).isZero();
			String selectedToken = csrf(selected.equals("first") ? firstPage : second);
			assertThat(post(client, "/logout", session, withCsrf(selectedToken)).statusCode()).isEqualTo(204);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(count("browser_session_ended")).isEqualTo(1);
		}
	}

	@Test
	void explicitSameValueWriteStillDetectsASilentlyIgnoredUpdateAfterAConcurrentChange() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String cookie = login(client);
			Session initial = this.repository.findById(sessionId(cookie));
			initial.setAttribute("browser.test", "original");
			save(initial);
			Session stale = this.repository.findById(sessionId(cookie));
			stale.setAttribute("browser.test", "original");
			Session concurrent = this.repository.findById(sessionId(cookie));
			concurrent.setAttribute("browser.test", "concurrent");
			save(concurrent);
			this.jdbc.sql("CREATE FUNCTION browser_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.attribute_name = 'browser.test' THEN RETURN NULL; END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER browser_test_fault BEFORE UPDATE ON iam_browser_session_attributes FOR EACH ROW EXECUTE FUNCTION browser_test_fault()").update();
			try { assertThatThrownBy(() -> save(stale)).isInstanceOf(IllegalStateException.class).hasMessageContaining("attribute was not stored"); }
			finally { removeFault("iam_browser_session_attributes"); }
			Session stored = this.repository.findById(sessionId(cookie));
			assertThat(stored.<String>getAttribute("browser.test")).isEqualTo("concurrent");
			assertThat(get(client, "/api/me", cookie).statusCode()).isEqualTo(200);
		}
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean
		ProfileRequestPause profileRequestPause() { return new ProfileRequestPause(); }

		@Bean
		CsrfRequestPause csrfRequestPause() { return new CsrfRequestPause(); }

		@Bean
		FilterRegistrationBean<CsrfRequestPause> csrfRequestPauseRegistration(CsrfRequestPause pause) {
			var registration = new FilterRegistrationBean<>(pause);
			registration.setOrder(SessionRepositoryFilter.DEFAULT_ORDER + 1);
			registration.setAsyncSupported(false);
			return registration;
		}

		@Bean
		WebMvcConfigurer concurrentRequestInterceptor(ProfileRequestPause pause) {
			return new WebMvcConfigurer() {
				@Override
				public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class ProfileRequestPause implements HandlerInterceptor {
		private volatile Pause active;

		Pause start() { this.active = new Pause(); return this.active; }

		@Override
		public boolean preHandle(jakarta.servlet.http.HttpServletRequest request,
				jakarta.servlet.http.HttpServletResponse response, Object handler) throws Exception {
			Pause pause = this.active;
			if (pause != null && request.getRequestURI().equals("/api/me") && "true".equals(request.getHeader("X-Test-Pause"))) {
				pause.entered.countDown();
				assertThat(pause.release.await(10, TimeUnit.SECONDS)).isTrue();
			}
			return true;
		}
	}

	static class CsrfRequestPause implements jakarta.servlet.Filter {
		private volatile Pause active;

		Pause start() { this.active = new Pause(); return this.active; }

		@Override
		public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response,
				jakarta.servlet.FilterChain chain) throws java.io.IOException, jakarta.servlet.ServletException {
			chain.doFilter(request, response);
			Pause pause = this.active;
			var http = (jakarta.servlet.http.HttpServletRequest) request;
			if (pause != null && http.getRequestURI().equals("/api/csrf") && "true".equals(http.getHeader("X-Test-Pause"))) {
				// Hold the token response before SessionRepositoryFilter saves its session.
				pause.entered.countDown();
				try { assertThat(pause.release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new java.io.IOException(ex); }
			}
		}
	}

	static class Pause {
		final CountDownLatch entered = new CountDownLatch(1);
		final CountDownLatch release = new CountDownLatch(1);
	}

	@Test
	void staleAnonymousRequestCannotRestoreTheSessionIdAfterLogin() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			String anonymous = cookie(page);
			Session stale = this.repository.findById(sessionId(anonymous));
			String session = cookie(post(client, "/login", anonymous, credentials("alice", PASSWORD, csrf(page))));
			assertThatThrownBy(() -> save(stale)).isInstanceOf(IllegalStateException.class);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/me", anonymous).statusCode()).isEqualTo(401);
		}
	}

	@Test
	void staleAuthenticatedRequestCannotResurrectALoggedOutSession() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			Session stale = this.repository.findById(sessionId(session));
			var page = get(client, "/api/csrf", session);
			assertThat(post(client, "/logout", session, withCsrf(csrf(page))).statusCode()).isEqualTo(204);
			assertThatThrownBy(() -> save(stale)).isInstanceOf(IllegalStateException.class);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(count("browser_session_ended")).isEqualTo(1);
		}
	}

	@Test
	void boundsJsonBodiesAndDoesNotTrustForwardedAddresses() throws Exception {
		try (var client = client()) {
			var oversized = post(client, "/login", null, "x".repeat(8193));
			assertThat(oversized.statusCode()).isEqualTo(413);
			assertError(oversized, "PAYLOAD_TOO_LARGE");
			var form = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/login"))
					.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString("username=alice")).build();
			assertThat(client.send(form, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			var page = get(client, "/api/csrf", null);
			var chunked = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/login"))
					.header("Content-Type", "application/json").header("Cookie", cookie(page)).header("X-CSRF-TOKEN", csrf(page))
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(new byte[8193]))).build();
			var bounded = client.send(chunked, HttpResponse.BodyHandlers.ofString());
			assertThat(bounded.statusCode()).isEqualTo(413);
			assertError(bounded, "PAYLOAD_TOO_LARGE");
			for (String forwarded : List.of("192.0.2.1", "192.0.2.2")) {
				var attempt = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/login"))
						.header("Content-Type", "application/json").header("Cookie", cookie(page)).header("X-CSRF-TOKEN", csrf(page))
						.header("X-Forwarded-For", forwarded)
						.POST(HttpRequest.BodyPublishers.ofString(credentials("unknown", PASSWORD, null).body())).build();
				assertThat(client.send(attempt, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
			}
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit WHERE dimension = 'source'").query(Long.class).single()).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT failures FROM iam_password_authentication_limit WHERE dimension = 'source'").query(Integer.class).single()).isEqualTo(2);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "null", "[]", "{}", "{", "{\"username\":\"alice\"}",
			"{\"username\":123,\"password\":\"secret\"}", "{\"username\":\"alice\",\"password\":null}",
			"{\"username\":\"alice\",\"password\":\"secret\",\"extra\":true}",
			"{\"username\":\"alice\",\"username\":\"bobby\",\"password\":\"secret\"}",
			"{\"username\":\"alice\",\"password\":\"secret\"} {}" })
	void rejectsMalformedJsonBeforeAttemptingAuthentication(String body) throws Exception {
		try (var client = client()) {
			var token = get(client, "/api/csrf", null);
			var response = post(client, this.port, "/login", cookie(token), new JsonRequest(body, csrf(token)));
			assertThat(response.statusCode()).isEqualTo(400);
			assertError(response, "BAD_REQUEST");
			assertThat(response.body()).doesNotContain("secret", "alice", "bobby");
			assertThat(count("password_auth_failed")).isZero();
			assertThat(count("browser_session_created")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "/login", "/logout", "/identity/app.js", "/identity/style.css" })
	void doesNotServeIdentityPagesOrAssets(String path) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var anonymous = get(client, path, null);
			assertThat(anonymous.statusCode()).isEqualTo(401);
			assertError(anonymous, "UNAUTHENTICATED");
			assertThat(anonymous.headers().firstValue("Location")).isEmpty();
			String session = login(client);
			var authenticated = get(client, path, session);
			assertThat(authenticated.statusCode()).isEqualTo(403);
			assertError(authenticated, "FORBIDDEN");
			assertThat(authenticated.headers().firstValue("Location")).isEmpty();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(count("browser_session_ended")).isZero();
		}
	}

	@Test
	void csrfTokensAreNotReadableByOtherOriginsAndPostIsNotAllowed() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/csrf"))
					.header("Origin", "https://untrusted.example").GET().build();
			var token = client.send(request, HttpResponse.BodyHandlers.ofString());
			assertThat(token.statusCode()).isEqualTo(200);
			assertThat(token.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
			assertThat(token.headers().firstValue("Cache-Control")).contains("no-store");
			var anonymousPost = post(client, "/api/csrf", cookie(token), withCsrf(csrf(token)));
			assertThat(anonymousPost.statusCode()).isEqualTo(401);
			assertError(anonymousPost, "UNAUTHENTICATED");
			String session = login(client);
			var authenticatedToken = get(client, "/api/csrf", session);
			var post = post(client, "/api/csrf", session, withCsrf(csrf(authenticatedToken)));
			assertThat(post.statusCode()).isEqualTo(403);
			assertError(post, "FORBIDDEN");
		}
	}

	@Test
	void aNewApplicationInstanceCanReadThePersistedSession() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			try (var restarted = new SpringApplicationBuilder(com.ixayda.iam.IamApplication.class)
					.properties(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
							"spring.datasource.password", this.postgres.getPassword(), "server.port", "0", "server.ssl.enabled", "true",
							"server.ssl.key-store", KEY_STORE.toUri().toString(), "server.ssl.key-store-password", "test-store-password",
							"spring.main.banner-mode", "off")).run()) {
				int restartedPort = ((WebServerApplicationContext) restarted).getWebServer().getPort();
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + restartedPort + "/api/me")).header("Cookie", session).GET().build();
				var profile = client.send(request, HttpResponse.BodyHandlers.ofString());
				assertThat(profile.statusCode()).isEqualTo(200);
				assertThat(profile.body()).contains("alice");
			}
			assertThat(count("browser_session_created")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { " alice", "alice ", "\talice", "alice\n" })
	void jsonLoginDoesNotTrimTheSubmittedUsername(String username) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			var response = post(client, "/login", cookie(page), credentials(username, PASSWORD, csrf(page)));
			assertThat(response.statusCode()).isEqualTo(401);
			assertThat(response.headers().firstValue("Location")).isEmpty();
			assertError(response, "INVALID_CREDENTIALS");
			assertThat(count("password_auth_failed")).isEqualTo(1);
			assertThat(count("browser_session_created")).isZero();
		}
	}

	@Test
	void profileAndCookieHeadersAreBoundedAndSensitiveResponsesCannotBeCached() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			var profile = get(client, "/api/me", session);
			assertThat(profile.headers().firstValue("Content-Security-Policy").orElseThrow()).contains("frame-ancestors 'none'", "form-action 'self'");
			assertThat(profile.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
			assertThat(profile.headers().firstValue("Referrer-Policy")).contains("no-referrer");
			assertThat(profile.headers().firstValue("Cache-Control")).contains("no-store");
			assertThat(profile.headers().firstValue("Strict-Transport-Security")).isPresent();
			var oversized = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/login"))
					.header("X-Oversized", "x".repeat(9000)).GET().build();
			var rejected = client.send(oversized, HttpResponse.BodyHandlers.ofString());
			assertThat(rejected.statusCode()).isEqualTo(400);
			assertThat(rejected.headers().allValues("Set-Cookie")).isEmpty();
		}
	}

	@Test
	void concurrentLogoutsRemoveTheSessionAtMostOnce() throws Exception {
		activeUser("alice");
		try (var client = client(); var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
			String session = login(client);
			String csrf = csrf(get(client, "/api/csrf", session));
			var start = new java.util.concurrent.CountDownLatch(1);
			var operations = java.util.stream.IntStream.range(0, 2).mapToObj(i -> executor.submit(() -> {
				assertThat(start.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
				return post(client, "/logout", session, withCsrf(csrf)).statusCode();
			})).toList();
			start.countDown();
			var outcomes = new java.util.ArrayList<Integer>();
			for (var result : operations) { outcomes.add(result.get(20, java.util.concurrent.TimeUnit.SECONDS)); }
			assertThat(outcomes).contains(204).allMatch(status -> status == 204 || status == 403 || status == 401);
			assertThat(count("browser_session_ended")).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
		}
	}

	@Test
	void loggingOutOneBrowserSessionKeepsTheOtherLoginUsable() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String current = login(client);
			String other = login(client);
			String csrf = csrf(get(client, "/api/csrf", current));
			assertThat(post(client, "/logout", current, withCsrf(csrf)).statusCode()).isEqualTo(204);
			assertThat(get(client, "/api/me", current).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", other).statusCode()).isEqualTo(200);
			assertThat(count("browser_session_created")).isEqualTo(2);
			assertThat(count("browser_session_ended")).isEqualTo(1);
		}
	}

	@Test
	void sessionReadFailureReturnsUnavailableWithoutAProfileOrCookie() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			this.jdbc.sql("ALTER TABLE iam_browser_session_attributes RENAME TO browser_test_unavailable").update();
			try {
				var unavailable = get(client, "/api/me", session);
				assertThat(unavailable.statusCode()).isEqualTo(503);
				assertSecurityHeaders(unavailable);
				assertError(unavailable, "SERVICE_UNAVAILABLE");
				assertThat(unavailable.headers().allValues("Set-Cookie")).isEmpty();
			}
			finally { this.jdbc.sql("ALTER TABLE browser_test_unavailable RENAME TO iam_browser_session_attributes").update(); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void documentationIsDisabledByDefaultEvenForAuthenticatedUsers() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client);
			for (String path : List.of("/v3/api-docs", "/v3/api-docs.yaml")) {
				assertThat(get(client, path, session).statusCode()).as(path).isEqualTo(404);
			}
			for (String path : List.of("/v3/api-docs/swagger-config", "/swagger-ui.html", "/swagger-ui/index.html", "/swagger-ui/swagger-ui-bundle.js")) {
				assertThat(get(client, path, null).statusCode()).as(path).isEqualTo(401);
				var response = get(client, path, session);
				assertThat(response.statusCode()).as(path).isEqualTo(403);
				assertSecurityHeaders(response);
				assertThat(response.headers().firstValue("Content-Security-Policy").orElseThrow()).doesNotContain("data:");
			}
		}
	}

	@Test
	void documentationDescribesTheActualProfileAndRequiresAValidSession() throws Exception {
		activeUser("alice");
		try (var client = client(); var application = new SpringApplicationBuilder(com.ixayda.iam.IamApplication.class)
				.profiles("documentation")
				.properties(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
						"spring.datasource.password", this.postgres.getPassword(), "server.port", "0", "server.ssl.enabled", "true",
						"server.ssl.key-store", KEY_STORE.toUri().toString(), "server.ssl.key-store-password", "test-store-password",
						"spring.main.banner-mode", "off")).run()) {
			int docsPort = ((WebServerApplicationContext) application).getWebServer().getPort();
			String session = login(client);
			for (String path : List.of("/v3/api-docs", "/v3/api-docs.yaml")) {
				assertThat(get(client, docsPort, path, null).statusCode()).as(path).isEqualTo(401);
			}
			var response = get(client, docsPort, "/v3/api-docs", session);
			assertThat(response.statusCode()).isEqualTo(200);
			assertSecurityHeaders(response);
			assertThat(response.body()).doesNotContain(PASSWORD, "Private Display");
			var specification = new JsonMapper().readTree(response.body());
			assertThat(specification.path("info").path("title").asText()).isEqualTo("IAM API");
			assertThat(specification.path("paths").propertyNames()).containsExactlyInAnyOrder("/api/me", "/api/csrf", "/login", "/logout", "/api/me/password", "/api/me/profile", "/api/me/mfa/recovery-codes", "/api/me/mfa/totp/enrollment", "/api/me/mfa/totp/enrollment/confirm", "/api/me/mfa/totp/enrollment/cancel", "/admin/mfa", "/api/admin/me", "/api/admin/audits", "/api/admin/users", "/api/admin/users/{userId}", "/api/admin/users/{userId}/disable", "/api/admin/users/{userId}/enable", "/api/admin/users/{userId}/profile", "/api/admin/users/{userId}/setup", "/api/admin/users/{userId}/setup/cancel", "/api/account-setup/complete", "/api/password-recovery/complete", "/api/admin/users/{userId}/password-recovery", "/api/admin/users/{userId}/password-recovery/cancel");
			assertThat(specification.path("paths").path("/api/me").propertyNames()).containsExactly("get");
			assertBrowserAuthenticationContract(specification);
			var search = specification.path("paths").path("/api/admin/users").path("get");
			var searchParameters = new java.util.HashSet<String>();
			for (var parameter : search.path("parameters")) {
				assertThat(parameter.path("in").asText()).isEqualTo("query");
				searchParameters.add(parameter.path("name").asText());
			}
			assertThat(searchParameters).containsExactlyInAnyOrder("keyword", "status", "pageSize", "cursor");

			assertThat(specification.path("paths").path("/api/admin/audits").propertyNames()).containsExactly("get");
			var auditQuery = specification.path("paths").path("/api/admin/audits").path("get");
			assertThat(auditQuery.path("operationId").asText()).isEqualTo("searchSecurityAudits");
			assertThat(auditQuery.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/SecurityAuditPageResponse");
			var auditParameters = new java.util.HashSet<String>();
			for (var parameter : auditQuery.path("parameters")) {
				assertThat(parameter.path("in").asText()).isEqualTo("query");
				auditParameters.add(parameter.path("name").asText());
				if (parameter.path("name").asText().equals("pageSize")) {
					assertThat(parameter.path("schema").path("minimum").asInt()).isEqualTo(1);
					assertThat(parameter.path("schema").path("maximum").asInt()).isEqualTo(100);
					assertThat(parameter.path("schema").path("default").asInt()).isEqualTo(20);
				}
				if (parameter.path("name").asText().equals("action")) {
					assertThat(parameter.path("schema").path("enum").size()).isEqualTo(com.ixayda.iam.model.SecurityAuditEvent.Action.values().length);
				}
			}
			assertThat(auditParameters).containsExactlyInAnyOrder("from", "until", "action", "outcome", "actor", "source", "targetUserId", "correlationId", "pageSize", "cursor");
			assertThat(specification.path("components").path("schemas").path("SecurityAuditPageResponse").path("properties").propertyNames()).containsExactlyInAnyOrder("items", "nextCursor");
			assertThat(specification.path("components").path("schemas").path("SecurityAuditEntryResponse").path("properties").propertyNames()).containsExactlyInAnyOrder("id", "action", "outcome", "targetUserId", "actor", "source", "correlationId", "recordedAt");
			var auditTarget = specification.path("components").path("schemas").path("SecurityAuditEntryResponse").path("properties").path("targetUserId");
			var auditContinuation = specification.path("components").path("schemas").path("SecurityAuditPageResponse").path("properties").path("nextCursor");
			assertThat(specification.path("openapi").asText()).startsWith("3.1.");
			for (var field : List.of(auditTarget, auditContinuation)) {
				var types = field.path("type");
				assertThat(types.isArray()).isTrue();
				assertThat(types.size()).isEqualTo(2);
				assertThat(List.of(types.path(0).asText(), types.path(1).asText())).containsExactlyInAnyOrder("string", "null");
			}
			assertThat(auditTarget.path("format").asText()).isEqualTo("uuid");

			assertFormOperationContract(specification, "/api/me/password", java.util.Set.of("currentPassword", "newPassword"));
			assertFormOperationContract(specification, "/api/me/profile", java.util.Set.of("displayName"));
			assertTotpEnrollmentContract(specification);
			assertFormOperationContract(specification, "/api/me/mfa/recovery-codes", java.util.Set.of("code"));
			assertThat(specification.path("paths").path("/api/me/mfa/recovery-codes").propertyNames()).containsExactly("post");
			var regeneration = specification.path("paths").path("/api/me/mfa/recovery-codes").path("post");
			assertThat(regeneration.path("operationId").asText()).isEqualTo("regenerateCurrentMfaRecoveryCodes");
			assertThat(regeneration.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityMfaRecoveryCodesResponse");
			var codeSet = specification.path("components").path("schemas").path("IdentityMfaRecoveryCodesResponse");
			assertThat(codeSet.path("properties").propertyNames()).containsExactlyInAnyOrder("generationId", "codes", "issuedAt");
			assertThat(codeSet.path("required").size()).isEqualTo(3);
			assertThat(codeSet.path("properties").path("generationId").path("format").asText()).isEqualTo("uuid");
			assertThat(codeSet.path("properties").path("issuedAt").path("format").asText()).isEqualTo("date-time");
			var recoveryCodes = codeSet.path("properties").path("codes");
			assertThat(recoveryCodes.path("minItems").asInt()).isEqualTo(10);
			assertThat(recoveryCodes.path("maxItems").asInt()).isEqualTo(10);
			var recoveryCodePattern = Pattern.compile(recoveryCodes.path("items").path("pattern").asText());
			assertThat(recoveryCodePattern.matcher("abcd-0123-abcd-0123-abcd-0123-abcd-0123").matches()).isTrue();
			assertThat(recoveryCodePattern.matcher("ABCD-0123-abcd-0123-abcd-0123-abcd-0123").matches()).isFalse();
			var issuanceCode = specification.path("components").path("schemas").path("IdentityMfaRecoveryCodeIssueRequest").path("properties").path("code");
			assertThat(issuanceCode.path("writeOnly").asBoolean()).isTrue();
			assertThat(issuanceCode.path("pattern").asText()).isEqualTo("^[0-9]{6}$");
			assertFormOperationContract(specification, "/admin/mfa", java.util.Set.of("code"));
			assertFormOperationContract(specification, "/api/admin/users", java.util.Set.of("username", "displayName", "code"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/disable", java.util.Set.of("code"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/enable", java.util.Set.of("code"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/profile", java.util.Set.of("displayName", "code"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/setup", java.util.Set.of("code"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/setup/cancel", java.util.Set.of("code"));
			assertFormOperationContract(specification, "/api/account-setup/complete", java.util.Set.of("userId", "token", "password"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/password-recovery", java.util.Set.of("code"));
			assertFormOperationContract(specification, "/api/admin/users/{userId}/password-recovery/cancel", java.util.Set.of("code"));
			var completion = specification.path("paths").path("/api/account-setup/complete").path("post");
			assertThat(completion.path("operationId").asText()).isEqualTo("completeUserSetup");
			assertThat(completion.has("security")).isTrue();
			assertThat(completion.path("security").size()).isZero();
			assertThat(completion.path("responses").path("204").has("content")).isFalse();
			var completionRequest = specification.path("components").path("schemas").path("IdentityUserSetupCompletionRequest");
			assertThat(completionRequest.path("properties").propertyNames()).containsExactlyInAnyOrder("userId", "token", "password");
			assertThat(completionRequest.path("required").size()).isEqualTo(3);
			assertThat(completionRequest.path("properties").path("token").path("writeOnly").asBoolean()).isTrue();
			assertThat(completionRequest.path("properties").path("password").path("writeOnly").asBoolean()).isTrue();
			var setup = specification.path("paths").path("/api/admin/users/{userId}/setup").path("post");
			assertThat(setup.path("operationId").asText()).isEqualTo("issueUserSetup");
			assertThat(setup.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityUserSetupResponse");
			var delivery = specification.path("components").path("schemas").path("IdentityUserSetupResponse");
			assertThat(delivery.path("properties").propertyNames()).containsExactlyInAnyOrder("userId", "token", "expiresAt");
			assertThat(delivery.path("required").size()).isEqualTo(3);
			assertThat(delivery.path("properties").path("token").path("writeOnly").asBoolean()).isFalse();
			var cancellation = specification.path("paths").path("/api/admin/users/{userId}/setup/cancel").path("post");
			assertThat(cancellation.path("operationId").asText()).isEqualTo("cancelUserSetup");
			assertThat(cancellation.path("responses").path("204").has("content")).isFalse();
			assertFormOperationContract(specification, "/api/password-recovery/complete", java.util.Set.of("userId", "token", "newPassword"));
			var recoveryCompletion = specification.path("paths").path("/api/password-recovery/complete").path("post");
			assertThat(recoveryCompletion.path("operationId").asText()).isEqualTo("completePasswordRecovery");
			assertThat(recoveryCompletion.has("security")).isTrue();
			assertThat(recoveryCompletion.path("security").size()).isZero();
			assertThat(recoveryCompletion.path("responses").path("204").has("content")).isFalse();
			assertThat(recoveryCompletion.path("responses").path("204").path("headers").has("Set-Cookie")).isTrue();
			assertThat(recoveryCompletion.path("responses").path("429").path("headers").has("Retry-After")).isTrue();
			var recoveryRequest = specification.path("components").path("schemas").path("IdentityPasswordRecoveryCompletionRequest");
			assertThat(recoveryRequest.path("properties").propertyNames()).containsExactlyInAnyOrder("userId", "token", "newPassword");
			assertThat(recoveryRequest.path("required").size()).isEqualTo(3);
			assertThat(recoveryRequest.path("properties").path("token").path("writeOnly").asBoolean()).isTrue();
			assertThat(recoveryRequest.path("properties").path("newPassword").path("writeOnly").asBoolean()).isTrue();

			var recovery = specification.path("paths").path("/api/admin/users/{userId}/password-recovery").path("post");
			assertThat(recovery.path("operationId").asText()).isEqualTo("issuePasswordRecovery");
			assertThat(recovery.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityPasswordRecoveryResponse");
			var recoveryDelivery = specification.path("components").path("schemas").path("IdentityPasswordRecoveryResponse");
			assertThat(recoveryDelivery.path("properties").propertyNames()).containsExactlyInAnyOrder("userId", "token", "expiresAt");
			assertThat(recoveryDelivery.path("required").size()).isEqualTo(3);
			assertThat(recoveryDelivery.path("properties").path("token").path("writeOnly").asBoolean()).isFalse();
			var recoveryCommand = specification.path("components").path("schemas").path("IdentityPasswordRecoveryManagementRequest");
			assertThat(recoveryCommand.path("properties").propertyNames()).containsExactly("code");
			assertThat(recoveryCommand.path("properties").path("code").path("writeOnly").asBoolean()).isTrue();
			var recoveryCancellation = specification.path("paths").path("/api/admin/users/{userId}/password-recovery/cancel").path("post");
			assertThat(recoveryCancellation.path("operationId").asText()).isEqualTo("cancelPasswordRecovery");
			assertThat(recoveryCancellation.path("responses").path("204").has("content")).isFalse();
			for (String path : List.of("/api/admin/users", "/api/admin/users/{userId}/disable", "/api/admin/users/{userId}/enable", "/api/admin/users/{userId}/profile", "/api/admin/users/{userId}/setup", "/api/admin/users/{userId}/setup/cancel", "/api/admin/users/{userId}/password-recovery", "/api/admin/users/{userId}/password-recovery/cancel")) {
				var responses = specification.path("paths").path(path).path("post").path("responses");
				for (String status : List.of("401", "403", "415")) {
					assertThat(responses.path(status).path("content").path("application/json").path("schema").path("$ref").asText())
							.as("POST %s %s", path, status).isEqualTo("#/components/schemas/IdentityErrorResponse");
				}
			}
			assertBrowserAuthenticationResponses(client, docsPort);
			var operation = specification.path("paths").path("/api/me").path("get");
			assertThat(operation.path("operationId").asText()).isEqualTo("getCurrentProfile");
			assertThat(operation.path("parameters").size()).isZero();
			for (String status : List.of("200", "401", "429", "503")) {
				assertThat(operation.path("responses").has(status)).as(status).isTrue();
			}
			assertThat(operation.path("responses").path("401").path("content").has("application/json")).isTrue();
			var schema = specification.path("components").path("schemas").path("IdentityProfileResponse");
			assertThat(schema.path("properties").size()).isEqualTo(3);
			assertThat(schema.path("properties").path("id").path("format").asText()).isEqualTo("uuid");
			assertThat(schema.path("required").size()).isEqualTo(3);
			var username = schema.path("properties").path("username");
			assertThat(username.path("minLength").asInt()).isEqualTo(3);
			assertThat(username.path("maxLength").asInt()).isEqualTo(64);
			var usernamePattern = Pattern.compile(username.path("pattern").asText());
			for (String valid : List.of("abc", "alice", "a_1", "test.user", "user-name", "a".repeat(64))) {
				assertThat(usernamePattern.matcher(valid).find()).as("valid username: %s", valid).isTrue();
			}
			for (String invalid : List.of("Alice", "abc!", "!abc", "a b", " alice", "alice ")) {
				assertThat(usernamePattern.matcher(invalid).find()).as("invalid username: %s", invalid).isFalse();
			}
			var security = specification.path("components").path("securitySchemes").path("browserSession");
			assertThat(security.path("type").asText()).isEqualTo("apiKey");
			assertThat(security.path("in").asText()).isEqualTo("cookie");
			assertThat(security.path("name").asText()).isEqualTo("__Host-IAMSESSION");
			assertThat(specification.path("security").get(0).has("browserSession")).isTrue();
			assertThat(get(client, docsPort, "/v3/api-docs.yaml", session).statusCode()).isEqualTo(200);
			for (String path : List.of("/v3/api-docs/swagger-config", "/swagger-ui.html", "/swagger-ui/index.html", "/swagger-ui/swagger-ui-bundle.js")) {
				assertThat(get(client, docsPort, path, null).statusCode()).as(path).isEqualTo(401);
				var rejected = get(client, docsPort, path, session);
				assertThat(rejected.statusCode()).as(path).isEqualTo(403);
				assertSecurityHeaders(rejected);
				assertThat(rejected.headers().firstValue("Content-Security-Policy").orElseThrow()).doesNotContain("data:");
			}
			assertThat(get(client, docsPort, "/api/me", session).headers().firstValue("Content-Security-Policy").orElseThrow())
					.doesNotContain("data:");
			for (String method : List.of("POST", "HEAD", "OPTIONS")) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + docsPort + "/v3/api-docs"))
						.header("Cookie", session).method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).as(method).isEqualTo(403);
			}
			var csrfResponse = get(client, docsPort, "/api/csrf", session);
			assertThat(csrfResponse.statusCode()).isEqualTo(200);
			String csrfToken = csrf(csrfResponse);
			var postWithCsrf = HttpRequest.newBuilder(URI.create("https://localhost:" + docsPort + "/v3/api-docs"))
					.header("Cookie", session).header("X-CSRF-TOKEN", csrfToken)
					.POST(HttpRequest.BodyPublishers.noBody()).build();
			assertThat(client.send(postWithCsrf, HttpResponse.BodyHandlers.ofString()).statusCode())
					.as("POST with a valid CSRF token").isEqualTo(403);
			assertThat(post(client, "/logout", session, withCsrf(csrfToken)).statusCode()).isEqualTo(204);
			assertThat(get(client, docsPort, "/v3/api-docs", session).statusCode()).isEqualTo(401);
		}
	}

	private static void assertBrowserAuthenticationContract(JsonNode specification) {
		for (String path : List.of("/login", "/logout")) {
			var item = specification.path("paths").path(path);
			assertThat(item.propertyNames()).containsExactly("post");
			var post = item.path("post");
			assertThat(post.path("security").isArray()).isTrue();
			assertThat(post.path("security").size()).isZero();
			for (String status : List.of("400", "401", "413", "429", "503")) {
				assertThat(post.path("responses").path(status).path("content").has("application/json"))
						.as("POST %s %s", path, status).isTrue();
			}
			assertThat(post.path("parameters").get(0).path("name").asText()).isEqualTo("X-CSRF-TOKEN");
			assertThat(post.path("parameters").get(0).path("required").asBoolean()).isTrue();
			assertThat(post.path("responses").has("403")).isTrue();
			assertThat(post.path("responses").has("204")).isTrue();
			assertThat(post.path("responses").path("204").has("content")).isFalse();
			assertThat(post.path("responses").has("302")).isFalse();
		}
		var login = specification.path("paths").path("/login").path("post");
		var body = login.path("requestBody").path("content").path("application/json").path("schema");
		assertThat(body.path("properties").propertyNames()).containsExactlyInAnyOrder("username", "password");
		assertThat(body.path("required").valueStream().map(JsonNode::asText).toList()).containsExactlyInAnyOrder("username", "password");
		assertThat(body.path("additionalProperties").asBoolean()).isFalse();
		assertThat(body.path("properties").path("password").path("writeOnly").asBoolean()).isTrue();
		assertThat(specification.path("paths").path("/logout").path("post").has("requestBody")).isFalse();
		var csrf = specification.path("paths").path("/api/csrf").path("get");
		assertThat(csrf.path("parameters").size()).isZero();
		assertThat(csrf.path("security").isArray()).isTrue();
		assertThat(csrf.path("security").size()).isZero();
	}


	private static void assertTotpEnrollmentContract(JsonNode specification) {
		String path = "/api/me/mfa/totp/enrollment";
		for (String suffix : List.of("", "/confirm", "/cancel")) {
			var item = specification.path("paths").path(path + suffix);
			assertThat(item.propertyNames()).containsExactly("post");
			// These operations inherit the application's browserSession security requirement.
			assertThat(item.path("post").has("security")).isFalse();
			for (var parameter : item.path("post").path("parameters")) {
				assertThat(parameter.path("in").asText()).isEqualTo("header");
				assertThat(parameter.path("name").asText()).isEqualTo("X-CSRF-TOKEN");
			}
			for (String status : List.of("400", "401", "403", "413", "415", "429", "503")) {
				assertThat(item.path("post").path("responses").has(status)).as(path + suffix + " " + status).isTrue();
			}
		}
		var begin = specification.path("paths").path(path).path("post");
		assertThat(begin.path("operationId").asText()).isEqualTo("beginCurrentTotpEnrollment");
		assertFormOperationContract(specification, path, java.util.Set.of("currentPassword"));
		var request = specification.path("components").path("schemas").path("IdentityTotpEnrollmentRequest");
		assertThat(request.path("required").valueStream().map(JsonNode::asText).toList()).containsExactly("currentPassword");
		assertThat(request.path("properties").path("currentPassword").path("format").asText()).isEqualTo("password");
		assertThat(request.path("properties").path("currentPassword").path("writeOnly").asBoolean()).isTrue();
		assertThat(begin.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityTotpEnrollmentResponse");
		var enrollment = specification.path("components").path("schemas").path("IdentityTotpEnrollmentResponse");
		assertThat(enrollment.path("properties").propertyNames()).containsExactlyInAnyOrder("factorId", "secret", "provisioningUri", "expiresAt");
		assertThat(enrollment.path("required").valueStream().map(JsonNode::asText).toList()).containsExactlyInAnyOrder("factorId", "secret", "provisioningUri", "expiresAt");
		assertThat(enrollment.path("properties").path("factorId").path("format").asText()).isEqualTo("uuid");
		assertThat(enrollment.path("properties").path("expiresAt").path("format").asText()).isEqualTo("date-time");
		assertThat(enrollment.path("properties").path("provisioningUri").path("format").asText()).isEqualTo("uri");
		assertThat(enrollment.path("properties").path("secret").path("writeOnly").asBoolean()).isFalse();
		assertThat(Pattern.compile(enrollment.path("properties").path("secret").path("pattern").asText()).matcher("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").matches()).isTrue();
		assertFormOperationContract(specification, path + "/confirm", java.util.Set.of("factorId", "code"));
		var confirm = specification.path("paths").path(path + "/confirm").path("post");
		assertThat(confirm.path("operationId").asText()).isEqualTo("confirmCurrentTotpEnrollment");
		assertThat(confirm.path("responses").path("200").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityMfaRecoveryCodesResponse");
		var confirmation = specification.path("components").path("schemas").path("IdentityTotpEnrollmentConfirmationRequest");
		assertThat(confirmation.path("required").size()).isEqualTo(2);
		assertThat(confirmation.path("properties").path("factorId").path("format").asText()).isEqualTo("uuid");
		assertThat(confirmation.path("properties").path("code").path("writeOnly").asBoolean()).isTrue();
		assertThat(Pattern.compile(confirmation.path("properties").path("code").path("pattern").asText()).matcher("123456").matches()).isTrue();
		assertFormOperationContract(specification, path + "/cancel", java.util.Set.of("factorId"));
		var cancel = specification.path("paths").path(path + "/cancel").path("post");
		assertThat(cancel.path("operationId").asText()).isEqualTo("cancelCurrentTotpEnrollment");
		assertThat(cancel.path("responses").path("204").has("content")).isFalse();
	}

	private static void assertFormOperationContract(JsonNode specification, String path, java.util.Set<String> fields) {
		var operation = specification.path("paths").path(path).path("post");
		var body = operation.path("requestBody");
		assertThat(body.path("required").asBoolean()).as(path).isTrue();
		var schema = body.path("content").path("application/x-www-form-urlencoded").path("schema");
		if (schema.has("$ref")) {
			schema = specification.path("components").path("schemas").path(schema.path("$ref").asText().substring("#/components/schemas/".length()));
		}
		assertThat(schema.path("properties").propertyNames()).as(path).containsExactlyInAnyOrderElementsOf(fields);
		for (var parameter : operation.path("parameters")) {
			assertThat(parameter.path("in").asText()).as(path).isNotEqualTo("query");
		}
	}

	private void assertBrowserAuthenticationResponses(HttpClient client, int port) throws Exception {
		var token = get(client, port, "/api/csrf", null);
		String anonymous = cookie(token);
		assertThat(post(client, port, "/login", anonymous, credentials("alice", PASSWORD, "invalid")).statusCode()).isEqualTo(403);
		var rejected = post(client, port, "/login", anonymous, credentials("alice", "wrong", csrf(token)));
		assertThat(rejected.statusCode()).isEqualTo(401);
		assertError(rejected, "INVALID_CREDENTIALS");
		assertThat(rejected.headers().firstValue("Location")).isEmpty();
		var signedIn = post(client, port, "/login", anonymous, credentials("alice", PASSWORD, csrf(token)));
		assertThat(signedIn.statusCode()).isEqualTo(204);
		assertThat(signedIn.headers().firstValue("Location")).isEmpty();
		String session = cookie(signedIn);
		assertThat(session).isNotEqualTo(anonymous);
		var fresh = get(client, port, "/api/csrf", session);
		assertThat(post(client, port, "/logout", session, withCsrf(csrf(token))).statusCode()).isEqualTo(403);
		var signedOut = post(client, port, "/logout", session, withCsrf(csrf(fresh)));
		assertThat(signedOut.statusCode()).isEqualTo(204);
		assertThat(signedOut.body()).isEmpty();
		assertThat(signedOut.headers().firstValue("Location")).isEmpty();
		assertThat(get(client, port, "/api/me", session).statusCode()).isEqualTo(401);
		var anonymousToken = get(client, port, "/api/csrf", null);
		assertThat(post(client, port, "/logout", cookie(anonymousToken), withCsrf(csrf(anonymousToken))).statusCode()).isEqualTo(204);
	}

	private HttpResponse<String> get(HttpClient client, int port, String path, String cookie) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + port + path)).timeout(Duration.ofSeconds(20));
		if (cookie != null) { request.header("Cookie", cookie); }
		return client.send(request.GET().build(), HttpResponse.BodyHandlers.ofString());
	}

	private static void assertSecurityHeaders(HttpResponse<?> response) {
		assertThat(response.headers().firstValue("Strict-Transport-Security").orElseThrow()).contains("max-age=");
		assertThat(response.headers().firstValue("Content-Security-Policy").orElseThrow())
				.contains("frame-ancestors 'none'", "form-action 'self'")
				.doesNotContain("'unsafe-inline'", "data:");
		assertThat(response.headers().firstValue("X-Frame-Options")).contains("DENY");
		assertThat(response.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
		assertThat(response.headers().firstValue("Referrer-Policy")).contains("no-referrer");
		assertThat(response.headers().firstValue("Cache-Control").orElseThrow()).contains("no-store");
	}


	private String login(HttpClient client) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}

	@SuppressWarnings("unchecked")
	private void save(Session session) { ((SessionRepository<Session>) this.repository).save(session); }

	private static String sessionId(String cookie) { return cookie.split("=", 2)[1]; }

	private void installFault(String mode, String table, String action, boolean logout) {
		String condition = table.equals("iam_security_audit") ? "IF NEW.action <> '" + action + "' THEN RETURN NEW; END IF; " : "";
		if (mode.equals("silent-csrf")) {
			condition = "IF NEW.attribute_name NOT LIKE '%CSRF_TOKEN' THEN RETURN NEW; END IF; ";
		}
		if (mode.equals("silent-version")) {
			condition = "IF NEW.attribute_name <> 'iam.credentialVersion' THEN RETURN NEW; END IF; ";
		}
		String result = mode.startsWith("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected session failure';";
		this.jdbc.sql("CREATE FUNCTION browser_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + condition + result + " END $$").update();
		String mutation = table.equals("iam_security_audit") ? "INSERT" : logout ? "DELETE" : "INSERT OR UPDATE";
		String timing = mode.equals("deferred-audit") ? "CREATE CONSTRAINT TRIGGER browser_test_fault AFTER " : "CREATE TRIGGER browser_test_fault BEFORE ";
		String deferral = mode.equals("deferred-audit") ? " DEFERRABLE INITIALLY DEFERRED" : "";
		this.jdbc.sql(timing + mutation + " ON " + table + deferral + " FOR EACH ROW EXECUTE FUNCTION browser_test_fault()").update();
	}

	private void removeFault(String table) {
		this.jdbc.sql("DROP TRIGGER IF EXISTS browser_test_fault ON " + table).update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS browser_test_fault()").update();
	}

	private IdentityUser activeUser(String name) {
		var pending = this.users.create(name, "Private Display", SYSTEM);
		var proof = this.setups.issue(pending.id(), SYSTEM);
		this.setups.complete(pending.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(pending.id()).orElseThrow();
	}

	private long count(String action) {
		return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action")
				.param("action", action).query(Long.class).single();
	}

	private HttpResponse<String> get(HttpClient client, String path, String cookie) throws Exception {
		var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (cookie != null) { builder.header("Cookie", cookie); }
		return client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString());
	}

	private HttpResponse<String> post(HttpClient client, String path, String cookie, String body) throws Exception {
		return post(client, this.port, path, cookie, new JsonRequest(body, null));
	}

	private HttpResponse<String> post(HttpClient client, String path, String cookie, JsonRequest request) throws Exception {
		return post(client, this.port, path, cookie, request);
	}

	private HttpResponse<String> post(HttpClient client, int port, String path, String cookie, JsonRequest request) throws Exception {
		var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + port + path)).timeout(Duration.ofSeconds(20))
				.header("Content-Type", "application/json");
		if (cookie != null) { builder.header("Cookie", cookie); }
		if (request.csrfToken() != null) { builder.header("X-CSRF-TOKEN", request.csrfToken()); }
		return client.send(builder.POST(request.body() == null ? HttpRequest.BodyPublishers.noBody()
				: HttpRequest.BodyPublishers.ofString(request.body())).build(), HttpResponse.BodyHandlers.ofString());
	}

	private static String csrf(HttpResponse<String> response) {
		assertThat(response.statusCode()).as("CSRF token response").isEqualTo(200);
		var body = new JsonMapper().readTree(response.body());
		assertThat(body.path("headerName").asText()).isEqualTo("X-CSRF-TOKEN");
		return body.path("token").asText();
	}

	private static String cookie(HttpResponse<String> response) {
		return response.headers().allValues("Set-Cookie").stream().filter(value -> value.startsWith("__Host-IAMSESSION="))
				.findFirst().orElseThrow().split(";", 2)[0];
	}

	private static JsonRequest credentials(String username, String password, String csrf) {
		return new JsonRequest(new JsonMapper().writeValueAsString(Map.of("username", username, "password", password)), csrf);
	}

	private static JsonRequest withCsrf(String token) { return new JsonRequest(null, token); }

	private static void assertError(HttpResponse<String> response, String code) {
		assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
		var error = new JsonMapper().readTree(response.body());
		assertThat(error.path("code").asText()).isEqualTo(code);
		assertThat(error.path("message").asText()).isNotBlank();
		assertThat(error.size()).isEqualTo(2);
	}

	private record JsonRequest(String body, String csrfToken) { }

	private static HttpClient client() throws Exception {
		KeyStore store = KeyStore.getInstance("PKCS12");
		try (InputStream input = Files.newInputStream(KEY_STORE)) { store.load(input, "test-store-password".toCharArray()); }
		var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trust.init(store);
		SSLContext ssl = SSLContext.getInstance("TLS");
		ssl.init(null, trust.getTrustManagers(), null);
		return HttpClient.newBuilder().sslContext(ssl).followRedirects(HttpClient.Redirect.NEVER)
				.version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build();
	}

	private static Path createKeyStore() {
		try {
			Path directory = Files.createTempDirectory("iam-test-tls-");
			Path store = directory.resolve("server.p12");
			Path log = directory.resolve("keytool.log");
			var process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
					"-genkeypair", "-alias", "localhost", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
					"-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-storetype", "PKCS12",
					"-keystore", store.toString(), "-storepass", "test-store-password", "-noprompt")
					.redirectErrorStream(true).redirectOutput(log.toFile()).start();
			if (!process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS) || process.exitValue() != 0) {
				process.destroyForcibly();
				throw new IllegalStateException("Test TLS certificate generation failed: " + Files.readString(log));
			}
			directory.toFile().deleteOnExit();
			log.toFile().deleteOnExit();
			store.toFile().deleteOnExit();
			return store;
		}
		catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
	}
}
