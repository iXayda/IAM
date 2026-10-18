package com.ixayda.iam.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityTotpReplacements;
import com.ixayda.iam.service.IdentityTotps;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUserStates;
import com.ixayda.iam.service.IdentityUsers;

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
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.SerializationUtils;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "iam.browser.requests-per-second=1000")
@Import({ PostgreSqlTestConfiguration.class, IdentityAdministratorAuthenticationIntegrationTests.ConcurrentRequests.class })
class IdentityAdministratorAuthenticationIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:admin-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private JdbcClient jdbc;
	@Autowired private IdentityTotpReplacements replacements;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityUserStates states;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private RequestPause pause;
	@Autowired private com.ixayda.iam.service.IdentityAdministratorAuthentications administratorAuthentications;

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
	void passwordAndTotpCreateARotatedPersistentAdministratorSessionWithFreshCsrf() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String passwordSession = login(client, "alice");
			assertThat(get(client, "/api/admin/me", passwordSession).statusCode()).isEqualTo(403);
			assertThat(get(client, "/admin/mfa", passwordSession).statusCode()).isEqualTo(403);
			var page = get(client, "/api/csrf", passwordSession);
			assertThat(page.statusCode()).isEqualTo(200);
			assertSecurityHeaders(page);
			String token = csrf(page);
			String code = otp(factor);
			var response = post(client, "/admin/mfa", passwordSession, mfaForm(code, token));
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.headers().firstValue("Location")).isEmpty();
			assertSecurityHeaders(response);
			String elevated = cookie(response);
			assertThat(elevated).isNotEqualTo(passwordSession);
			assertThat(get(client, "/api/me", passwordSession).statusCode()).isEqualTo(401);
			var identity = get(client, "/api/admin/me", elevated);
			assertThat(identity.statusCode()).isEqualTo(200);
			assertThat(identity.body()).contains(factor.userId().toString(), "alice").doesNotContain("factorId", "credentialVersion", code, factor.secret());
			assertThat(post(client, "/admin/mfa", elevated, mfaForm(code, token)).statusCode()).isEqualTo(403);
			var evidence = (IdentityAdministratorAuthentication) attribute(elevated, IdentityAdministratorSessions.AUTHENTICATION);
			assertThat(evidence.userId()).isEqualTo(factor.userId());
			var security = (SecurityContext) attribute(elevated, IdentityBrowserSessions.SECURITY_CONTEXT);
			assertThat(security.getAuthentication().getAuthorities()).extracting("authority")
					.containsExactlyInAnyOrder("FACTOR_PASSWORD", "FACTOR_TOTP", "ROLE_IAM_ADMIN");
			assertThat(security.getAuthentication().getCredentials()).isNull();
			assertThat(events("admin_mfa_authenticated")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a").query(String.class).list().toString())
					.doesNotContain(PASSWORD, factor.secret(), code);
			assertThat(post(client, "/api/me/profile", elevated, "displayName=Updated&_csrf=" + encode(csrf(get(client, "/api/csrf", elevated)))).statusCode()).isEqualTo(204);
			assertThat(get(client, "/api/admin/me", elevated).statusCode()).isEqualTo(200);
			assertThat(attribute(elevated, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(evidence.passwordAuthenticatedAt());
		}
	}

	@Test
	void ordinaryUsersAndAnonymousRequestsCannotEnterTheAdministratorFlow() throws Exception {
		administrator();
		var user = this.users.create("bobby", "Bob", SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var client = client()) {
			assertThat(get(client, "/admin/mfa", null).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/admin/me", null).statusCode()).isEqualTo(401);
			String session = login(client, "bobby");
			assertThat(get(client, "/admin/mfa", session).statusCode()).isEqualTo(403);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			String token = csrf(get(client, "/api/csrf", session));
			assertThat(post(client, "/admin/mfa", session, mfaForm("000000", token)).statusCode()).isEqualTo(403);
			assertThat(events("admin_access_denied")).isGreaterThanOrEqualTo(5);
			assertThat(events("admin_mfa_authenticated")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "storage", "silent-storage", "attribute", "audit", "silent-audit", "deferred-audit" })
	void anyStorageOrAuditFailureRollsBackTheCodeSessionRotationAndManagementGrant(String fault) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			String body = mfaForm(otp(factor), csrf(get(client, "/api/csrf", session)));
			long before = this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single();
			installFault(fault);
			try {
				var rejected = post(client, "/admin/mfa", session, body);
				assertThat(rejected.statusCode()).isEqualTo(503);
				assertThat(rejected.body()).contains("SERVICE_UNAVAILABLE");
				assertThat(rejected.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(rejected.headers().firstValue("Location")).isEmpty();
				assertSecurityHeaders(rejected);
				assertThat(events("admin_mfa_authenticated")).isZero();
				assertThat(this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single()).isEqualTo(before);
			}
			finally { this.jdbc.sql("DROP FUNCTION admin_mfa_test_fault() CASCADE").update(); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			assertThat(post(client, "/admin/mfa", session, body).statusCode()).isEqualTo(204);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "expired", "future", "different-user", "different-factor", "different-version", "different-password-time", "missing" })
	void staleOrMismatchedMfaEvidenceNeverGrantsManagementPermission(String state) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var previous = (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			var modified = new IdentityAdministratorAuthentication(state.equals("different-user") ? UUID.randomUUID() : previous.userId(),
					state.equals("different-factor") ? UUID.randomUUID() : previous.factorId(),
					previous.credentialVersion() + (state.equals("different-version") ? 1 : 0),
					previous.passwordAuthenticatedAt() + (state.equals("different-password-time") ? 1 : 0),
					state.equals("expired") ? Instant.now().minusSeconds(901) : state.equals("future") ? Instant.now().plusSeconds(60) : previous.verifiedAt());
			if (state.equals("missing")) {
				this.jdbc.sql("DELETE FROM iam_browser_session_attributes WHERE attribute_name = :name")
						.param("name", IdentityAdministratorSessions.AUTHENTICATION).update();
			}
			else { replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION, modified); }
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void aTotpCodeCanElevateOnlyOneOfTwoConcurrentPasswordSessions() throws Exception {
		var factor = administrator();
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String first = login(client, "alice"); String second = login(client, "alice");
			String code = otp(factor);
			String firstBody = mfaForm(code, csrf(get(client, "/api/csrf", first)));
			String secondBody = mfaForm(code, csrf(get(client, "/api/csrf", second)));
			var start = new CountDownLatch(1);
			var one = executor.submit(() -> { start.await(10, TimeUnit.SECONDS); return post(client, "/admin/mfa", first, firstBody).statusCode(); });
			var two = executor.submit(() -> { start.await(10, TimeUnit.SECONDS); return post(client, "/admin/mfa", second, secondBody).statusCode(); });
			start.countDown();
			assertThat(List.of(one.get(20, TimeUnit.SECONDS), two.get(20, TimeUnit.SECONDS))).containsExactlyInAnyOrder(204, 400);
			assertThat(events("admin_mfa_authenticated")).isEqualTo(1);
		}
	}

	@Test
	void invalidCodesShareTheExistingAccountFailureBudget() throws Exception {
		administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			for (int i = 0; i < 5; i++) {
				var rejected = post(client, "/admin/mfa", session, mfaForm("invalid", token));
				assertThat(rejected.statusCode()).isEqualTo(400);
				assertThat(rejected.body()).contains("MFA_REJECTED", "Verification rejected").doesNotContain("<form", "invalid");
			}
			assertThat(post(client, "/admin/mfa", session, mfaForm("invalid", token)).statusCode()).isEqualTo(429);
			assertThat(events("totp_auth_failed")).isEqualTo(5);
			assertThat(events("totp_auth_throttled")).isEqualTo(1);
			assertThat(events("admin_mfa_authenticated")).isZero();
		}
	}

	@Test
	void requiresCsrfAndFormEncodingAndNeverBindsAuthenticationFromHeadersOrExtraFields() throws Exception {
		administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			assertThat(post(client, "/admin/mfa", session, "code=123456").statusCode()).isEqualTo(403);
			for (String extra : List.of("userId=" + UUID.randomUUID(), "code=654321", "_csrf=again", "factorId=" + UUID.randomUUID(), "role=ADMIN")) {
				assertThat(post(client, "/admin/mfa", session, mfaForm("123456", token) + "&" + extra).statusCode()).isEqualTo(400);
			}
			assertThat(post(client, "/admin/mfa?code=123456", session, "_csrf=" + encode(token)).statusCode()).isEqualTo(400);
			var header = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/admin/mfa"))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded").header("code", "123456")
					.POST(HttpRequest.BodyPublishers.ofString("_csrf=" + encode(token))).build();
			assertThat(client.send(header, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			for (String method : List.of("PUT", "PATCH", "DELETE")) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/admin/mfa"))
						.header("Cookie", session).header("X-CSRF-TOKEN", token).method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
			}
			var json = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/admin/mfa"))
					.header("Cookie", session).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			assertThat(events("admin_mfa_authenticated")).isZero();
		}
	}

	@Test
	void expiredMfaCanBeRenewedWithoutExtendingThePasswordSessionLifetime() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var previous = (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			long originalTime = Instant.now().minusSeconds(1200).toEpochMilli();
			replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, originalTime);
			replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION, new IdentityAdministratorAuthentication(
					previous.userId(), previous.factorId(), previous.credentialVersion(), originalTime, Instant.now().minusSeconds(901)));
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			String token = csrf(get(client, "/api/csrf", session));
			var renewed = post(client, "/admin/mfa", session, mfaForm(otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1), token));
			assertThat(renewed.statusCode()).isEqualTo(204);
			String current = cookie(renewed);
			assertThat(get(client, "/api/admin/me", current).statusCode()).isEqualTo(200);
			assertThat(attribute(current, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(originalTime);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
		}
	}

	@Test
	void persistedAuthoritiesAloneCannotCreateAnMfaSessionAndPasswordReloginClearsPriorMfa() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String verified = elevate(client, login(client, "alice"), factor);
			Object privileged = attribute(verified, IdentityBrowserSessions.SECURITY_CONTEXT);
			String passwordOnly = login(client, "alice");
			replaceAttribute(passwordOnly, IdentityBrowserSessions.SECURITY_CONTEXT, privileged);
			assertThat(get(client, "/api/admin/me", passwordOnly).statusCode()).isEqualTo(403);
			String token = csrf(get(client, "/api/csrf", verified));
			var relogin = post(client, "/login", verified, credentials("alice", PASSWORD, token));
			assertThat(relogin.statusCode()).isEqualTo(204);
			String current = cookie(relogin);
			assertThat(attribute(current, IdentityAdministratorSessions.AUTHENTICATION)).isNull();
			assertThat(get(client, "/api/admin/me", current).statusCode()).isEqualTo(403);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "membership", "password", "factor", "logout", "disable", "replacement" })
	void currentDatabaseStateAndNormalLifecycleOperationsRevokeManagementAccess(String operation) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			if (operation.equals("membership")) {
				this.jdbc.sql("DELETE FROM iam_administrator").update();
			}
			else if (operation.equals("factor")) {
				this.jdbc.sql("DELETE FROM iam_mfa_recovery_code").update();
				this.jdbc.sql("UPDATE iam_user_totp SET factor_id = :id").param("id", UUID.randomUUID()).update();
			}
			else if (operation.equals("password")) {
				String token = csrf(get(client, "/api/csrf", session));
				assertThat(post(client, "/api/me/password", session, "currentPassword=" + encode(PASSWORD)
						+ "&newPassword=" + encode("New violet lanterns above the lake") + "&_csrf=" + encode(token)).statusCode()).isEqualTo(204);
			}
			else if (operation.equals("logout")) {
				assertThat(post(client, "/logout", session, "_csrf=" + encode(csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(204);
			}
			else if (operation.equals("disable")) {
				var peer = this.users.create("bobby", "Bob", SYSTEM);
				var setup = this.setups.issue(peer.id(), SYSTEM);
				this.setups.complete(peer.id(), setup.token(), PASSWORD, "internal:test", UUID.randomUUID());
				this.jdbc.sql("INSERT INTO iam_administrator(user_id) VALUES (:id)").param("id", peer.id()).update();
				var peerFactor = this.totps.beginEnrollment(peer.id(), SYSTEM);
				assertThat(this.totps.confirmEnrollment(peer.id(), peerFactor.factorId(), otp(peerFactor), totpContext())).isTrue();
				assertThat(this.states.disable(factor.userId(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
			}
			else {
				var replacement = this.replacements.begin(factor.userId(), PASSWORD,
						otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1), totpContext()).orElseThrow();
				assertThat(this.replacements.complete(factor.userId(), replacement.replacementId(), replacement.token(),
						otp(replacement.enrollment()), totpContext())).isPresent();
			}
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(
					operation.equals("membership") || operation.equals("factor") ? 403 : 401);
		}
	}

	@Test
	void aFreshApplicationContextRestoresOnlyCurrentPersistedMfaEvidence() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			try (var fresh = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.SERVLET).run(
					"--server.port=0", "--server.ssl.enabled=true", "--server.ssl.key-store=" + KEY_STORE.toUri(),
					"--server.ssl.key-store-password=test-store-password", "--iam.totp.key-file=" + KEY_FILE,
					"--spring.datasource.url=" + this.postgres.getJdbcUrl(), "--spring.datasource.username=" + this.postgres.getUsername(),
					"--spring.datasource.password=" + this.postgres.getPassword())) {
				int previousPort = this.port;
				try {
					this.port = Integer.parseInt(fresh.getEnvironment().getProperty("local.server.port"));
					assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
					this.jdbc.sql("DELETE FROM iam_administrator").update();
					assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
				}
				finally { this.port = previousPort; }
			}
		}
	}

	@Test
	void aConcurrentRequestLoadedBeforeElevationCannotRestoreTheOldSessionOrEraseTheNewGrant() throws Exception {
		var factor = administrator();
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			this.pause.start();
			var stale = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/me"))
					.header("Cookie", session).header("X-Test-Pause", "true").GET().build();
			var pending = executor.submit(() -> client.send(stale, HttpResponse.BodyHandlers.ofString()));
			String current;
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				current = elevate(client, session, factor);
			}
			finally { this.pause.release.countDown(); }
			var old = pending.get(20, TimeUnit.SECONDS);
			assertThat(old.statusCode()).isEqualTo(503);
			assertThat(old.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/admin/me", current).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "logout", "membership" })
	void anAlreadyAuthorizedMfaRequestRechecksTheSessionAndMembershipBeforeConsumingItsCode(String operation) throws Exception {
		var factor = administrator();
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			long before = this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single();
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/admin/mfa"))
					.header("Cookie", session).header("X-Test-Pause", "true").header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString(mfaForm(otp(factor), token))).build();
			var pending = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (operation.equals("logout")) { assertThat(post(client, "/logout", session, "_csrf=" + encode(token)).statusCode()).isEqualTo(204); }
				else { this.jdbc.sql("DELETE FROM iam_administrator").update(); }
			}
			finally { this.pause.release.countDown(); }
			assertThat(pending.get(20, TimeUnit.SECONDS).statusCode()).isEqualTo(operation.equals("logout") ? 401 : 400);
			assertThat(this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single()).isEqualTo(before);
			assertThat(events("admin_mfa_authenticated")).isZero();
			assertThat(events("admin_access_denied")).isEqualTo(operation.equals("logout") ? 1 : 0);
			assertThat(events("admin_mfa_rejected")).isEqualTo(operation.equals("membership") ? 1 : 0);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent" })
	void aRevokedMfaRequestRemainsRejectedWhenDenialAuditingIsUnavailable(String mode) throws Exception {
		var factor = administrator();
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			long before = this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single();
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/admin/mfa"))
					.header("Cookie", session).header("X-Test-Pause", "true").header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString(mfaForm(otp(factor), token))).build();
			var pending = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				try {
					assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
					assertThat(post(client, "/logout", session, "_csrf=" + encode(token)).statusCode()).isEqualTo(204);
					installAccessDenialFault(mode);
				}
				finally { this.pause.release.countDown(); }
				var response = pending.get(20, TimeUnit.SECONDS);
				assertThat(response.statusCode()).isEqualTo(503);
				assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
				assertSecurityHeaders(response);
				assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
				assertThat(response.headers().firstValue("Location")).isEmpty();
				assertThat(this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single()).isEqualTo(before);
				assertThat(events("admin_access_denied")).isZero();
				assertThat(events("admin_mfa_authenticated")).isZero();
			}
			finally { this.jdbc.sql("DROP FUNCTION IF EXISTS admin_denial_fault() CASCADE").update(); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "unchanged", "missing", "failure" })
	void aTrustedAdapterThatDoesNotPersistARotatedSessionCannotConsumeTheCodeOrReportAuthentication(String failure) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			String id = session.substring(session.indexOf('=') + 1);
			long before = this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single();
			assertThatIllegalStateException().isThrownBy(() -> this.administratorAuthentications.authenticate(factor.userId(), id,
					(Long) attribute(session, IdentityBrowserSessions.CREDENTIAL_VERSION), (Long) attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT),
					otp(factor), totpContext(), evidence -> {
						if (failure.equals("failure")) { throw new IllegalStateException("Adapter failed"); }
						return failure.equals("unchanged") ? id : UUID.randomUUID().toString();
					}));
			assertThat(this.jdbc.sql("SELECT last_used_step FROM iam_user_totp").query(Long.class).single()).isEqualTo(before);
			assertThat(events("admin_mfa_authenticated")).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@CsvSource({
			"expired, identity", "expired, form", "expired, submit",
			"version, identity", "version, form", "version, submit",
			"missing-time, identity", "missing-time, form", "missing-time, submit",
			"missing-version, identity", "missing-version, form", "missing-version, submit"
	})
	void invalidPasswordSessionsAreRejectedAndAuditedBeforeEnteringAdministratorEndpoints(String state, String endpoint) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			if (state.equals("expired")) {
				replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, Instant.now().minusSeconds(28801).toEpochMilli());
			}
			else if (state.equals("version")) {
				replaceAttribute(session, IdentityBrowserSessions.CREDENTIAL_VERSION, (Long) attribute(session, IdentityBrowserSessions.CREDENTIAL_VERSION) + 1);
			}
			else {
				this.jdbc.sql("DELETE FROM iam_browser_session_attributes WHERE session_primary_id = (SELECT primary_id FROM iam_browser_session WHERE session_id = :id) AND attribute_name = :name")
						.param("id", session.substring(session.indexOf('=') + 1))
						.param("name", state.equals("missing-time") ? IdentityBrowserSessions.AUTHENTICATED_AT : IdentityBrowserSessions.CREDENTIAL_VERSION).update();
			}
			var response = endpoint.equals("submit") ? post(client, "/admin/mfa", session, "code=000000")
					: get(client, endpoint.equals("identity") ? "/api/admin/me" : "/admin/mfa", session);
			assertThat(response.statusCode()).isEqualTo(401);
			assertSecurityHeaders(response);
			assertThat(events("admin_access_denied")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT target_user_id FROM iam_security_audit WHERE action = 'admin_access_denied'").query(UUID.class).single()).isEqualTo(factor.userId());
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", factor.userId().toString()).query(Long.class).single()).isZero();
			assertThat(events("admin_mfa_authenticated")).isZero();
			assertThat(events("totp_auth_failed")).isZero();
		}
	}

	@Test
	void invalidOrdinarySessionsDoNotCreateAdministratorAccessDenialEvents() throws Exception {
		administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, Instant.now().minusSeconds(28801).toEpochMilli());
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(events("admin_access_denied")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "error, false", "silent, false", "error, true", "silent, true" })
	void unavailableAccessDenialAuditingFailsClosed(String mode, boolean expiredPasswordSession) throws Exception {
		administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			if (expiredPasswordSession) {
				replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, Instant.now().minusSeconds(28801).toEpochMilli());
			}
			installAccessDenialFault(mode);
			try {
				var response = get(client, "/api/admin/me", session);
				assertThat(response.statusCode()).isEqualTo(503);
				assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
				assertSecurityHeaders(response);
				assertThat(events("admin_access_denied")).isZero();
			}
			finally { this.jdbc.sql("DROP FUNCTION admin_denial_fault() CASCADE").update(); }
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(expiredPasswordSession ? 401 : 403);
		}
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean RequestPause administratorRequestPause() { return new RequestPause(); }
		@Bean WebMvcConfigurer administratorRequestInterceptor(RequestPause pause) {
			return new WebMvcConfigurer() {
				@Override public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class RequestPause implements HandlerInterceptor {
		private volatile CountDownLatch entered;
		private volatile CountDownLatch release;
		void start() { this.entered = new CountDownLatch(1); this.release = new CountDownLatch(1); }
		@Override public boolean preHandle(jakarta.servlet.http.HttpServletRequest request,
				jakarta.servlet.http.HttpServletResponse response, Object handler) throws Exception {
			if ("true".equals(request.getHeader("X-Test-Pause"))) {
				this.entered.countDown();
				assertThat(this.release.await(10, TimeUnit.SECONDS)).isTrue();
			}
			return true;
		}
	}

	private IdentityTotpEnrollment administrator() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(userId, PASSWORD, totpContext()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor), totpContext()).orElseThrow();
		// Start each independent HTTP scenario with the current time step unused.
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
		var response = post(client, "/admin/mfa", session, mfaForm(otp(factor), csrf(get(client, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}

	private Object attribute(String cookie, String name) {
		byte[] value = this.jdbc.sql("SELECT a.attribute_bytes FROM iam_browser_session_attributes a JOIN iam_browser_session s ON s.primary_id = a.session_primary_id WHERE s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).query(byte[].class).optional().orElse(null);
		return value == null ? null : SerializationUtils.deserialize(value);
	}

	private void replaceAttribute(String cookie, String name, Object value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update();
	}

	private void installAccessDenialFault(String mode) {
		this.jdbc.sql("CREATE FUNCTION admin_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'admin_access_denied' THEN "
				+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected denial audit failure';") + " END IF; RETURN NEW; END $$").update();
		this.jdbc.sql("CREATE TRIGGER admin_denial_fault BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION admin_denial_fault()").update();
	}

	private void installFault(String fault) {
		boolean session = fault.contains("storage"); boolean attribute = fault.equals("attribute");
		String table = session ? "iam_browser_session" : attribute ? "iam_browser_session_attributes" : "iam_security_audit";
		String body = session ? (fault.equals("silent-storage") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected session failure';")
				: attribute ? "IF NEW.attribute_name = 'iam.administratorAuthentication' THEN RETURN NULL; END IF; RETURN NEW;"
				: "IF NEW.action <> 'admin_mfa_authenticated' THEN RETURN NEW; END IF; " + (fault.equals("silent-audit") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected audit failure';");
		this.jdbc.sql("CREATE FUNCTION admin_mfa_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		String trigger = fault.equals("deferred-audit") ? "CREATE CONSTRAINT TRIGGER admin_mfa_test_fault AFTER INSERT ON " + table + " DEFERRABLE INITIALLY DEFERRED"
				: "CREATE TRIGGER admin_mfa_test_fault BEFORE " + (session ? "UPDATE" : attribute ? "INSERT OR UPDATE" : "INSERT") + " ON " + table;
		this.jdbc.sql(trigger + " FOR EACH ROW EXECUTE FUNCTION admin_mfa_test_fault()").update();
	}

	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action").param("action", action).query(Long.class).single(); }
	private static String mfaForm(String code, String token) { return "code=" + encode(code) + "&_csrf=" + encode(token); }
	private static TotpAuthenticationContext totpContext() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }

	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-admin-mfa-test-", ".key"); byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
			Files.write(path, bytes); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}

	private static String otp(IdentityTotpEnrollment factor) {
		return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30));
	}

	private static String otp(IdentityTotpEnrollment factor, long step) {
		byte[] counter = new byte[8]; for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(factor.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(java.util.Locale.ROOT, "%06d", number % 1_000_000);
	}

}
