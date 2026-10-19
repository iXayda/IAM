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
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.dto.IdentityTotpRecoveryCompletionRequest;
import com.ixayda.iam.dto.IdentityTotpRecoveryRequest;
import com.ixayda.iam.dto.IdentityTotpRecoveryResponse;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityTotpRecovery;
import com.ixayda.iam.model.IdentityTotpReplacement;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityMfaRecoveryCodes;
import com.ixayda.iam.service.IdentityTotpRecoverySessions;
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
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
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
@Import({ PostgreSqlTestConfiguration.class, IdentityTotpRecoveryControllerIntegrationTests.ConcurrentRequests.class })
class IdentityTotpRecoveryControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/me/mfa/totp/recovery";
	private static final String SOURCE = "browser:totp-recovery";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:recovery-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityTotpRecoverySessions recoveries;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private RequestPause pause;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
		properties.add("iam.totp-recovery.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void recoveringAnAuthenticatorRevokesOnlyItsOwnersSessionsAndDoesNotGrantManagementAccess(boolean administrator) throws Exception {
		UUID userId = activeUser("alice");
		UUID otherId = activeUser("bobby");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		if (administrator) { this.jdbc.sql("INSERT INTO iam_administrator(user_id) VALUES (:id)").param("id", userId).update(); }
		try (var client = client()) {
			String session = login(client, "alice");
			String another = login(client, "alice");
			String other = login(client, "bobby");
			Object authenticatedAt = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			long version = version(userId);
			var pending = begin(client, session, oldCodes);
			assertThat(pending.enrollment().factorId()).isNotEqualTo(old.factorId());
			assertThat(pending.enrollment().expiresAt()).isBetween(Instant.now().plusSeconds(590), Instant.now().plusSeconds(601));
			assertThat(pending.token()).matches("[A-Za-z0-9_-]{43}");
			assertThat(pending.enrollment().secret()).matches("[A-Z2-7]{32}");
			assertThat(pending.enrollment().provisioningUri()).contains("otpauth://totp/IAM:" + userId, "secret=" + pending.enrollment().secret(), "issuer=IAM");
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(codeCount()).isEqualTo(10);
			assertThat(consumedCodeCount(userId)).isEqualTo(1);
			assertThat(version(userId)).isEqualTo(version);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(authenticatedAt);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isNull();
			assertThat(get(client, "/api/me", another).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			assertThat(this.recoveryCodes.consume(userId, oldCodes.codes().getFirst(), recoveryContext())).isEmpty();
			assertThat(this.recoveryCodes.consume(userId, oldCodes.codes().get(1), recoveryContext())).isPresent();
			assertThat(this.totps.verify(userId, freshTotp(old), context())).isPresent();
			var response = complete(client, session, pending);
			assertThat(response.statusCode()).isEqualTo(200);
			assertSecurityHeaders(response);
			assertThat(response.headers().firstValue("Location")).isEmpty();
			assertThat(response.headers().allValues("Set-Cookie")).anySatisfy(cookie -> assertThat(cookie).contains("__Host-IAMSESSION=", "Max-Age=0", "Secure", "HttpOnly", "SameSite=Lax", "Path=/"));
			Map<String, Object> body = JsonPath.read(response.body(), "$");
			assertThat(body).containsOnlyKeys("generationId", "codes", "issuedAt");
			List<String> codes = JsonPath.read(response.body(), "$.codes");
			assertThat(codes).hasSize(10).doesNotHaveDuplicates().doesNotContainAnyElementsOf(oldCodes.codes());
			assertThat(factorId(userId)).isEqualTo(pending.enrollment().factorId());
			assertThat(version(userId)).isEqualTo(version + 1);
			assertThat(pendingCount()).isZero();
			assertThat(sessionCount(userId)).isZero();
			assertThat(sessionCount(otherId)).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", another).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", other).statusCode()).isEqualTo(200);
			assertThat(this.totps.verify(userId, otp(pending.enrollment(), lastUsedStep(userId)), context())).isEmpty();
			assertThat(this.recoveryCodes.consume(userId, oldCodes.codes().get(2), recoveryContext())).isEmpty();
			assertThat(this.recoveryCodes.consume(userId, codes.getFirst(), recoveryContext())).isPresent();
			assertThat(this.recoveryCodes.consume(userId, codes.getFirst(), recoveryContext())).isEmpty();
			assertThat(events("totp_recovery_started")).isEqualTo(1);
			assertThat(events("totp_recovery_completed")).isEqualTo(1);
			assertThat(events("mfa_recovery_code_consumed")).isEqualTo(1);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
			assertThat(events("browser_sessions_revoked")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT count(DISTINCT correlation_id) FROM iam_security_audit WHERE source = :source AND action IN ('totp_recovery_completed', 'mfa_recovery_codes_generated', 'browser_sessions_revoked')").param("source", SOURCE).query(Long.class).single()).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE source = :source").param("source", SOURCE).query(String.class).list()).containsOnly("user:" + userId);
			assertThat(response.body()).doesNotContain(pending.token(), pending.enrollment().secret(), PASSWORD, "credentialVersion", "userId");
			String newSession = login(client, "alice");
			assertRejected(complete(client, newSession, pending), 400);
			assertThat(get(client, "/api/admin/me", newSession).statusCode()).isEqualTo(403);
		}
	}

	@ParameterizedTest
	@CsvSource({ "missing, valid", "empty, valid", "wrong, valid", "valid, missing", "valid, empty", "valid, malformed", "valid, wrong", "valid, used", "valid, uppercase", "valid, whitespace" })
	void everyStartRequiresTheCurrentPasswordAndAnUnusedOwnerRecoveryCode(String password, String code) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		if (code.equals("used")) { assertThat(this.recoveryCodes.consume(userId, oldCodes.codes().getFirst(), recoveryContext())).isPresent(); }
		try (var client = client()) {
			String session = login(client, "alice");
			long authenticatedAt = System.currentTimeMillis() - 7_200_000;
			setAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, authenticatedAt);
			String suppliedPassword = password.equals("missing") ? null : password.equals("empty") ? "" : password.equals("valid") ? PASSWORD : "wrong password";
			String suppliedCode = switch (code) {
				case "missing" -> null;
				case "empty" -> "";
				case "malformed" -> "bad";
				case "wrong" -> "0000-0000-0000-0000-0000-0000-0000-0000";
				case "uppercase" -> "A" + oldCodes.codes().getFirst().substring(1);
				case "whitespace" -> " " + oldCodes.codes().getFirst();
				default -> oldCodes.codes().getFirst();
			};
			assertRejected(post(client, PATH, session, startBody(suppliedPassword, suppliedCode, csrf(get(client, "/api/csrf", session)))), 400);
			assertThat(pendingCount()).isZero();
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(failures("recovery", "account")).isEqualTo(1);
			assertThat(failures("password", "account")).isEqualTo(password.equals("valid") ? 0 : 1);
			assertThat(consumedCodeCount(userId)).isEqualTo(code.equals("used") ? 1 : 0);
			assertThat(events("totp_recovery_started")).isZero();
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(authenticatedAt);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing-password", "missing-code", "wrong-body" })
	void headersCannotSupplyOrOverrideStartCredentials(String scenario) throws Exception {
		UUID userId = activeUser("alice");
		var factor = activeFactor(userId);
		var oldCodes = issueOldCodes(factor);
		try (var client = client()) {
			String session = login(client, "alice");
			String body = startBody(scenario.equals("missing-password") ? null : scenario.equals("wrong-body") ? "wrong" : PASSWORD,
					scenario.equals("missing-code") ? null : oldCodes.codes().getFirst(), csrf(get(client, "/api/csrf", session)));
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("currentPassword", PASSWORD).header("recoveryCode", oldCodes.codes().getFirst()).POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 400);
			assertThat(pendingCount()).isZero();
		}
	}

	@Test
	void restartingRequiresAnotherUnusedRecoveryCodeAndReplacesThePriorProof() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var first = begin(client, session, oldCodes);
			assertRejected(start(client, session, oldCodes), 400);
			assertThat(this.jdbc.sql("SELECT recovery_id FROM iam_totp_recovery").query(UUID.class).single()).isEqualTo(first.recoveryId());
			var second = begin(client, session, oldCodes, 1);
			assertThat(second.recoveryId()).isNotEqualTo(first.recoveryId());
			assertThat(second.token()).isNotEqualTo(first.token());
			assertThat(second.enrollment().secret()).isNotEqualTo(first.enrollment().secret());
			assertThat(consumedCodeCount(userId)).isEqualTo(2);
			assertRejected(complete(client, session, first), 400);
			assertThat(complete(client, session, second).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "none", "pending" })
	void anActiveOldFactorIsRequired(String state) throws Exception {
		UUID userId = activeUser("alice");
		if (state.equals("pending")) { this.totps.beginEnrollment(userId, SYSTEM); }
		try (var client = client()) {
			String session = login(client, "alice");
			assertRejected(post(client, PATH, session, startBody(PASSWORD, "0000-0000-0000-0000-0000-0000-0000-0000", csrf(get(client, "/api/csrf", session)))), 400);
			assertThat(pendingCount()).isZero();
			assertThat(failures("recovery", "account")).isEqualTo(1);
			assertThat(events("totp_recovery_started")).isZero();
		}
	}

	@Test
	void csrfHeadersAndCompleteUppercaseUuidsAreAcceptedWithoutHeaderCredentialBinding() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var beginRequest = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
					.POST(HttpRequest.BodyPublishers.ofString("currentPassword=" + encode(PASSWORD) + "&recoveryCode=" + oldCodes.codes().getFirst())).build();
			var response = client.send(beginRequest, HttpResponse.BodyHandlers.ofString());
			assertThat(response.statusCode()).isEqualTo(200);
			String secret = JsonPath.read(response.body(), "$.secret");
			String recoveryId = JsonPath.read(response.body(), "$.recoveryId");
			String token = JsonPath.read(response.body(), "$.token");
			var enrollment = new IdentityTotpEnrollment(userId, UUID.fromString(JsonPath.read(response.body(), "$.factorId")), secret, JsonPath.read(response.body(), "$.provisioningUri"), Instant.parse(JsonPath.read(response.body(), "$.expiresAt")));
			var completeRequest = HttpRequest.newBuilder(URI.create(base() + "/complete")).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
					.POST(HttpRequest.BodyPublishers.ofString("recoveryId=" + recoveryId.toUpperCase(java.util.Locale.ROOT) + "&token=" + token + "&code=" + otp(enrollment, step()))).build();
			assertThat(client.send(completeRequest, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
			assertThat(sessionCount(userId)).isZero();
		}
	}

	@Test
	void recoveryProofsAreBoundToTheirOwnerAndCanBeCompletedFromAnotherValidOwnerSession() throws Exception {
		UUID userId = activeUser("alice");
		activeUser("bobby");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			String sameOwner = login(client, "alice");
			String other = login(client, "bobby");
			var pending = begin(client, session, oldCodes);
			assertRejected(complete(client, other, pending), 400);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(complete(client, sameOwner, pending).statusCode()).isEqualTo(200);
			assertThat(get(client, "/api/me", other).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "wrong-id", "wrong-token", "missing-id", "missing-token", "missing-code", "malformed-token", "expired" })
	void invalidCompletionPreservesTheOldFactorRecoveryCodesAndSessions(String reason) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			if (reason.equals("expired")) { this.jdbc.sql("WITH instant AS MATERIALIZED (SELECT clock_timestamp() - INTERVAL '1 second' AS expiry) UPDATE iam_totp_recovery SET issued_at = expiry - INTERVAL '10 minutes', expires_at = expiry FROM instant").update(); }
			String body = (reason.equals("missing-id") ? "" : "recoveryId=" + (reason.equals("wrong-id") ? UUID.randomUUID() : pending.recoveryId()) + "&")
					+ (reason.equals("missing-token") ? "" : "token=" + encode(reason.equals("wrong-token") ? "A".repeat(43) : reason.equals("malformed-token") ? "bad" : pending.token()) + "&")
					+ (reason.equals("missing-code") ? "" : "code=" + otp(pending.enrollment(), step()) + "&") + "_csrf=" + encode(csrf(get(client, "/api/csrf", session)));
			assertRejected(post(client, PATH + "/complete", session, body), 400);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(codeCount()).isEqualTo(10);
			assertThat(version(userId)).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			assertThat(failures("totp", "account")).isEqualTo(1);
			assertThat(events("totp_recovery_completed")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "recoveryId", "token", "code" })
	void headersCannotSupplyMissingCompletionFields(String missing) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			String body = (missing.equals("recoveryId") ? "" : "recoveryId=" + pending.recoveryId() + "&")
					+ (missing.equals("token") ? "" : "token=" + pending.token() + "&")
					+ (missing.equals("code") ? "" : "code=" + otp(pending.enrollment(), step()) + "&") + "_csrf=" + encode(csrf(get(client, "/api/csrf", session)));
			var request = HttpRequest.newBuilder(URI.create(base() + "/complete")).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("recoveryId", pending.recoveryId().toString()).header("token", pending.token()).header("code", otp(pending.enrollment(), step()))
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 400);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "/complete" })
	void csrfQueriesDuplicatesExtraFieldsAndMediaBoundariesPreventBusinessChanges(String suffix) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			String csrf = csrf(get(client, "/api/csrf", session));
			String fields = suffix.isEmpty() ? "currentPassword=" + encode(PASSWORD) + "&recoveryCode=" + oldCodes.codes().getFirst()
					: "recoveryId=" + pending.recoveryId() + "&token=" + pending.token() + "&code=" + otp(pending.enrollment(), step());
			String body = fields + "&_csrf=" + encode(csrf);
			assertThat(post(client, PATH + suffix, session, fields).statusCode()).isEqualTo(403);
			assertThat(post(client, PATH + suffix + "?code=123456", session, body).statusCode()).isEqualTo(400);
			for (String extra : List.of("userId=" + userId, "source=forged", "actor=forged", "code=123456", "recoveryCode=" + oldCodes.codes().getFirst(), "_csrf=" + encode(csrf), "factorId=" + old.factorId())) {
				assertThat(post(client, PATH + suffix, session, body + "&" + extra).statusCode()).isEqualTo(400);
			}
			var json = HttpRequest.newBuilder(URI.create(base() + suffix)).header("Cookie", session).header("X-CSRF-TOKEN", csrf)
					.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			var unacceptable = HttpRequest.newBuilder(URI.create(base() + suffix)).header("Cookie", session).header("Accept", "text/html")
					.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertThat(client.send(unacceptable, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(406);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(pendingCount()).isEqualTo(1);
			assertThat(events("totp_recovery_completed")).isZero();
			assertThat(failures("totp", "account")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "/complete" })
	void anonymousRequestsAndOtherHttpMethodsAreDenied(String suffix) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			var anonymous = get(client, "/api/csrf", null);
			assertThat(post(client, PATH + suffix, cookie(anonymous), "_csrf=" + encode(csrf(anonymous))).statusCode()).isEqualTo(401);
			String session = login(client, "alice");
			for (String method : List.of("GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE")) {
				var request = HttpRequest.newBuilder(URI.create(base() + suffix)).header("Cookie", session).header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session)))
						.method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).as(method).isEqualTo(403);
			}
			assertThat(pendingCount()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "1-1-1-1-1", "not-a-uuid", "00000000000000000000000000000001", "", "%2000000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000001%20" })
	void incompleteOrMalformedRecoveryIdsDoNotReachVerification(String id) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			assertThat(post(client, PATH + "/complete", session, "recoveryId=" + id + "&token=" + pending.token() + "&code=" + otp(pending.enrollment(), step()) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(400);
			assertThat(failures("totp", "account")).isZero();
			assertThat(factorId(userId)).isEqualTo(old.factorId());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "/complete" })
	void existingRecoveryAndTotpBudgetsBlockCorrectCredentialsAtTheirRespectiveStages(String suffix) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			for (int i = 0; i < 5; i++) {
				if (suffix.isEmpty()) { assertThat(this.recoveryCodes.consume(userId, "bad", recoveryContext())).isEmpty(); }
				else { assertThat(this.totps.verify(userId, "bad", context())).isEmpty(); }
			}
			String body = suffix.isEmpty() ? startBody(PASSWORD, oldCodes.codes().get(1), csrf(get(client, "/api/csrf", session))) : completionBody(pending, csrf(get(client, "/api/csrf", session)));
			assertRejected(post(client, PATH + suffix, session, body), 429);
			assertThat(failures(suffix.isEmpty() ? "recovery" : "totp", "account")).isEqualTo(5);
			assertThat(events(suffix.isEmpty() ? "mfa_recovery_code_throttled" : "totp_recovery_throttled")).isEqualTo(1);
			assertThat(consumedCodeCount(userId)).isEqualTo(1);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
		}
	}

	@Test
	void passwordBudgetIsSharedWithLoginAndCannotBeBypassedByAValidRecoveryCode() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var anonymous = get(client, "/api/csrf", null);
			for (int i = 0; i < 10; i++) { assertThat(post(client, "/login", cookie(anonymous), credentials("alice", "wrong", csrf(anonymous))).statusCode()).isEqualTo(401); }
			assertRejected(start(client, session, oldCodes), 429);
			assertThat(failures("password", "account")).isEqualTo(10);
			assertThat(failures("recovery", "account")).isEqualTo(1);
			assertThat(events("password_auth_throttled")).isEqualTo(1);
			assertThat(pendingCount()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "recovery", "password" })
	void forwardedHeadersCannotBypassSourceBudgetsOrCreateNewAccountBuckets(String budget) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			if (budget.equals("recovery")) { assertThat(this.recoveryCodes.consume(UUID.randomUUID(), "bad", recoveryContext())).isEmpty(); }
			String table = budget.equals("recovery") ? "iam_mfa_recovery_limit" : "iam_password_authentication_limit";
			var accounts = this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t WHERE dimension = 'account' ORDER BY subject_key").query(String.class).list();
			this.jdbc.sql("UPDATE " + table + " SET failures = :limit WHERE dimension = 'source'").param("limit", budget.equals("password") ? 50 : 30).update();
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Forwarded-For", "192.0.2.90").header("Forwarded", "for=192.0.2.90")
					.POST(HttpRequest.BodyPublishers.ofString(startBody(PASSWORD, oldCodes.codes().getFirst(), csrf(get(client, "/api/csrf", session))))).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 429);
			assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t WHERE dimension = 'account' ORDER BY subject_key").query(String.class).list()).isEqualTo(accounts);
			assertThat(pendingCount()).isZero();
		}
	}

	@Test
	void concurrentCompletionPublishesOneRecoverySetAndCannotResurrectASession() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			String body = completionBody(pending, csrf(get(client, "/api/csrf", session)));
			this.pause.start(2);
			var request = HttpRequest.newBuilder(URI.create(base() + "/complete")).timeout(Duration.ofSeconds(20))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded").header("X-Test-Pause", "true")
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return client.send(request, HttpResponse.BodyHandlers.ofString()); });
			var second = executor.submit(() -> { start.await(); return client.send(request, HttpResponse.BodyHandlers.ofString()); });
			start.countDown();
			try {
				// Both requests pass authentication and CSRF before either can revoke the session.
				assertThat(this.pause.entered.await(5, TimeUnit.SECONDS)).isTrue();
			}
			finally { this.pause.release.countDown(); }
			var responses = List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS));
			assertThat(responses.stream().filter(response -> response.statusCode() == 200)).hasSize(1);
			assertThat(responses.stream().map(HttpResponse::statusCode).toList()).allMatch(status -> status == 200 || status == 401);
			assertThat(events("totp_recovery_completed")).isEqualTo(1);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
			assertThat(codeCount()).isEqualTo(10);
			assertThat(sessionCount(userId)).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, version", "begin, disabled", "begin, session", "begin, absolute-expiry", "complete, version", "complete, disabled", "complete, session", "complete, absolute-expiry" })
	void sessionStateIsRecheckedAfterHttpAuthorization(String operation, String change) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			var pending = operation.equals("complete") ? begin(client, session, oldCodes) : null;
			String csrf = csrf(get(client, "/api/csrf", session));
			String body = pending == null ? startBody(PASSWORD, oldCodes.codes().getFirst(), csrf) : completionBody(pending, csrf);
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create(base() + (pending == null ? "" : "/complete")))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded").header("X-Test-Pause", "true")
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (change.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
				else if (change.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled'").update(); }
				else if (change.equals("session")) { this.jdbc.sql("DELETE FROM iam_browser_session").update(); }
				else { this.pause.expirePassword = true; }
			}
			finally { this.pause.release.countDown(); }
			assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(401);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(events("totp_recovery_completed")).isZero();
			assertThat(events("totp_recovery_started")).isEqualTo(pending == null ? 0 : 1);
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, pending, error", "begin, pending, silent", "begin, pending, deferred", "begin, audit, error", "begin, audit, silent", "begin, audit, deferred", "begin, password-audit, error", "begin, password-audit, silent", "begin, password-audit, deferred", "begin, session, error", "begin, session, silent", "begin, session, deferred", "begin, code, error", "begin, code, silent", "begin, code, deferred", "begin, code-audit, error", "begin, code-audit, silent", "begin, code-audit, deferred",
			"complete, pending, error", "complete, pending, silent", "complete, pending, deferred", "complete, factor, error", "complete, factor, silent", "complete, factor, deferred", "complete, password, error", "complete, password, silent", "complete, password, deferred", "complete, codes, error", "complete, codes, silent", "complete, codes, deferred", "complete, audit, error", "complete, audit, silent", "complete, audit, deferred", "complete, session, error", "complete, session, silent", "complete, session, deferred" })
	void persistenceFaultsRollbackTheWorkflowAndPublishNoSecrets(String operation, String fault, String mode) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = operation.equals("complete") ? begin(client, session, oldCodes) : null;
			var snapshot = snapshot(userId);
			String csrf = csrf(get(client, "/api/csrf", session));
			String body = pending == null ? startBody(PASSWORD, oldCodes.codes().getFirst(), csrf) : completionBody(pending, csrf);
			String table = fault.equals("pending") ? "iam_totp_recovery" : fault.equals("factor") ? "iam_user_totp" : fault.equals("password") ? "iam_password" : (fault.equals("codes") || fault.equals("code")) ? "iam_mfa_recovery_code" : fault.endsWith("audit") ? "iam_security_audit" : "iam_browser_session";
			String mutation = fault.equals("session") ? (pending == null ? "UPDATE" : "DELETE") : fault.equals("pending") ? (pending == null ? "INSERT" : "DELETE") : (fault.equals("password") || fault.equals("code")) ? "UPDATE" : fault.equals("factor") ? "DELETE" : "INSERT";
			String auditAction = fault.equals("password-audit") ? "password_authenticated" : fault.equals("code-audit") ? "mfa_recovery_code_consumed" : pending == null ? "totp_recovery_started" : "totp_recovery_completed";
			String guard = fault.endsWith("audit") ? "IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + auditAction + "' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION recovery_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected recovery failure';") + " END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER recovery_fault AFTER " : "CREATE TRIGGER recovery_fault BEFORE ") + mutation + " ON " + table + (mode.equals("deferred") ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION recovery_fault()").update();
			try { assertUnavailable(post(client, PATH + (pending == null ? "" : "/complete"), session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION recovery_fault() CASCADE").update(); }
			assertThat(snapshot(userId)).isEqualTo(snapshot);
			assertThat(events("totp_recovery_started")).isEqualTo(pending == null ? 0 : 1);
			assertThat(events("totp_recovery_completed")).isZero();
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			assertThat(sessionCount(userId)).isEqualTo(1);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			if (pending != null) { assertThat(complete(client, session, pending).statusCode()).isEqualTo(200); }
			else { assertThat(start(client, session, oldCodes).statusCode()).isEqualTo(200); }
		}
	}

	@ParameterizedTest
	@CsvSource({ "password_auth_failed, error", "password_auth_failed, silent", "password_auth_failed, deferred", "mfa_recovery_code_failed, error", "mfa_recovery_code_failed, silent", "mfa_recovery_code_failed, deferred", "totp_recovery_failed, error", "totp_recovery_failed, silent", "totp_recovery_failed, deferred" })
	void requiredFailureAuditFaultsRollbackTheirCounters(String action, String mode) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = action.equals("totp_recovery_failed") ? begin(client, session, oldCodes) : null;
			var snapshot = snapshot(userId);
			long passwordFailures = failures("password", "account");
			long totpFailures = failures("totp", "account");
			long recoveryFailures = failures("recovery", "account");
			String csrf = csrf(get(client, "/api/csrf", session));
			String body = pending == null ? startBody(action.equals("password_auth_failed") ? "wrong" : PASSWORD, "bad", csrf)
					: "recoveryId=" + pending.recoveryId() + "&token=" + pending.token() + "&code=bad&_csrf=" + encode(csrf);
			this.jdbc.sql("CREATE FUNCTION recovery_failure_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + action + "' THEN RETURN NEW; END IF; " + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected failure audit';") + " END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER recovery_failure_audit AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER recovery_failure_audit BEFORE INSERT ON iam_security_audit") + " FOR EACH ROW EXECUTE FUNCTION recovery_failure_audit()").update();
			try { assertUnavailable(post(client, PATH + (pending == null ? "" : "/complete"), session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION recovery_failure_audit() CASCADE").update(); }
			assertThat(snapshot(userId)).isEqualTo(snapshot);
			assertThat(failures("password", "account")).isEqualTo(passwordFailures);
			assertThat(failures("totp", "account")).isEqualTo(totpFailures);
			assertThat(failures("recovery", "account")).isEqualTo(recoveryFailures);
			assertThat(events(action)).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "recovery, error", "recovery, silent", "recovery, deferred", "totp, error", "totp, silent", "totp, deferred", "password, error", "password, silent", "password, deferred" })
	void requiredThrottleAuditFaultsFailClosed(String budget, String mode) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			String table = budget.equals("recovery") ? "iam_mfa_recovery_limit" : budget.equals("totp") ? "iam_totp_authentication_limit" : "iam_password_authentication_limit";
			this.jdbc.sql("UPDATE " + table + " SET failures = :limit WHERE dimension = 'source'").param("limit", budget.equals("password") ? 50 : 30).update();
			String action = budget.equals("recovery") ? "mfa_recovery_code_throttled" : budget.equals("totp") ? "totp_recovery_throttled" : "password_auth_throttled";
			String csrf = csrf(get(client, "/api/csrf", session));
			String body = budget.equals("totp") ? completionBody(pending, csrf) : startBody(PASSWORD, oldCodes.codes().getFirst(), csrf);
			this.jdbc.sql("CREATE FUNCTION recovery_throttle_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + action + "' THEN RETURN NEW; END IF; " + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected throttle audit';") + " END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER recovery_throttle_audit AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER recovery_throttle_audit BEFORE INSERT ON iam_security_audit") + " FOR EACH ROW EXECUTE FUNCTION recovery_throttle_audit()").update();
			try { assertUnavailable(post(client, PATH + (budget.equals("totp") ? "/complete" : ""), session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION recovery_throttle_audit() CASCADE").update(); }
			assertThat(failures(budget, "source")).isEqualTo(budget.equals("password") ? 50 : 30);
			assertThat(failures("totp", "account")).isZero();
			assertThat(events(action)).isZero();
			assertThat(pendingCount()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent", "deferred" })
	void aFailedRestartRestoresThePreviouslyDeliveredProofAndRecoveryCodeState(String mode) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			var snapshot = snapshot(userId);
			String body = startBody(PASSWORD, oldCodes.codes().get(1), csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("CREATE FUNCTION recovery_restart_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected restart failure';") + " END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER recovery_restart_fault AFTER UPDATE ON iam_browser_session DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER recovery_restart_fault BEFORE UPDATE ON iam_browser_session") + " FOR EACH ROW EXECUTE FUNCTION recovery_restart_fault()").update();
			try { assertUnavailable(post(client, PATH, session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION recovery_restart_fault() CASCADE").update(); }
			assertThat(snapshot(userId)).isEqualTo(snapshot);
			assertThat(events("totp_recovery_started")).isEqualTo(1);
			assertThat(complete(client, session, pending).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void aPendingProtectionKeyFaultPublishesNoSecretsAndPreservesTheStoredState() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			this.jdbc.sql("UPDATE iam_totp_recovery SET key_id = repeat('0', 64)").update();
			var snapshot = snapshot(userId);
			assertUnavailable(complete(client, session, pending));
			assertThat(snapshot(userId)).isEqualTo(snapshot);
			assertThat(sessionCount(userId)).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, source", "begin, account", "begin, password-source", "begin, password-account", "begin, user", "begin, session", "complete, source", "complete, account", "complete, user", "complete, session" })
	void idleExpiryWhileWaitingForLocksRejectsTheOperation(String operation, String locked) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			var pending = operation.equals("complete") ? begin(client, session, oldCodes) : null;
			// Create all budget rows without consuming a valid recovery code.
			if (pending == null) { assertRejected(post(client, PATH, session, startBody("wrong", "bad", csrf(get(client, "/api/csrf", session)))), 400); }
			String csrf = csrf(get(client, "/api/csrf", session));
			String body = pending == null ? startBody(PASSWORD, oldCodes.codes().getFirst(), csrf) : completionBody(pending, csrf);
			long deadline = System.currentTimeMillis() + 2000;
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :deadline").param("deadline", deadline).update();
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			String sql = locked.equals("user") ? "SELECT id FROM iam_user WHERE id = ? FOR UPDATE" : locked.equals("session") ? "SELECT session_id FROM iam_browser_session WHERE session_id = ? FOR UPDATE"
					: "SELECT subject_key FROM " + (locked.startsWith("password-") ? "iam_password_authentication_limit" : pending == null ? "iam_mfa_recovery_limit" : "iam_totp_authentication_limit") + " WHERE dimension = ? FOR UPDATE";
			try (var statement = blocker.prepareStatement(sql)) {
				statement.setObject(1, locked.equals("user") ? userId : locked.equals("session") ? session.substring(session.indexOf('=') + 1) : locked.replace("password-", "")); statement.executeQuery().close();
			}
			var waiting = executor.submit(() -> post(client, PATH + (pending == null ? "" : "/complete"), session, body));
			try {
				awaitBlocked(pid);
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(401);
			}
			finally { blocker.rollback(); }
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(events("totp_recovery_completed")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, idle, pending", "begin, absolute, password-audit", "begin, absolute, session", "begin, idle, session", "begin, proof, session", "begin, idle, code", "complete, idle, factor", "complete, absolute, codes", "complete, idle, audit", "complete, absolute, session", "complete, proof, audit" })
	void deadlinesCrossedDuringPersistenceRollbackAllChanges(String operation, String expiration, String waitingAt) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			var pending = operation.equals("complete") ? begin(client, session, oldCodes) : null;
			String csrf = csrf(get(client, "/api/csrf", session));
			long deadline = System.currentTimeMillis() + 2500;
			if (expiration.equals("idle")) { this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :deadline").param("deadline", deadline).update(); }
			if (expiration.equals("absolute")) { setAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, deadline - 28_800_000); }
			if (expiration.equals("proof") && pending != null) { this.jdbc.sql("UPDATE iam_totp_recovery SET issued_at = to_timestamp(:deadline / 1000.0) - INTERVAL '10 minutes', expires_at = to_timestamp(:deadline / 1000.0)").param("deadline", deadline).update(); }
			String body = pending == null ? startBody(PASSWORD, oldCodes.codes().getFirst(), csrf) : completionBody(pending, csrf);
			var snapshot = snapshot(userId);
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173844)"); }
			if (expiration.equals("proof") && pending == null) {
				this.jdbc.sql("CREATE FUNCTION recovery_deadline() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source = '" + SOURCE + "' AND NEW.action = 'totp_recovery_started' THEN UPDATE iam_totp_recovery SET issued_at = to_timestamp(" + deadline + " / 1000.0) - INTERVAL '10 minutes', expires_at = to_timestamp(" + deadline + " / 1000.0); END IF; RETURN NEW; END $$").update();
				this.jdbc.sql("CREATE TRIGGER recovery_deadline BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION recovery_deadline()").update();
			}
			String table = waitingAt.equals("pending") ? "iam_totp_recovery" : waitingAt.equals("factor") ? "iam_user_totp" : (waitingAt.equals("codes") || waitingAt.equals("code")) ? "iam_mfa_recovery_code" : waitingAt.endsWith("audit") ? "iam_security_audit" : "iam_browser_session";
			String mutation = waitingAt.equals("code") ? "UPDATE" : waitingAt.equals("factor") || (waitingAt.equals("session") && pending != null) ? "DELETE" : waitingAt.equals("session") ? "UPDATE" : "INSERT";
			String action = waitingAt.equals("password-audit") ? "password_authenticated" : pending == null ? "totp_recovery_started" : "totp_recovery_completed";
			String guard = waitingAt.endsWith("audit") ? "IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + action + "' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION recovery_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173844); RETURN " + (mutation.equals("DELETE") ? "OLD" : "NEW") + "; END $$").update();
			this.jdbc.sql("CREATE TRIGGER recovery_wait BEFORE " + mutation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION recovery_wait()").update();
			var waiting = executor.submit(() -> post(client, PATH + (pending == null ? "" : "/complete"), session, body));
			try {
				awaitBlocked(pid);
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertUnavailable(waiting.get(15, TimeUnit.SECONDS));
			}
			finally {
				blocker.rollback();
				this.jdbc.sql("DROP FUNCTION recovery_wait() CASCADE").update();
				if (expiration.equals("proof") && pending == null) { this.jdbc.sql("DROP FUNCTION recovery_deadline() CASCADE").update(); }
			}
			assertThat(snapshot(userId)).isEqualTo(snapshot);
			assertThat(events("totp_recovery_started")).isEqualTo(pending == null ? 0 : 1);
			assertThat(events("totp_recovery_completed")).isZero();
			assertThat(events("mfa_recovery_codes_generated")).isZero();
		}
	}

	@Test
	void theRequestFinalizerDoesNotRepeatTheCommittedStartSessionSave() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			String body = startBody(PASSWORD, oldCodes.codes().getFirst(), csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("CREATE SEQUENCE recovery_session_saves").update();
			this.jdbc.sql("CREATE FUNCTION recovery_second_save() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('recovery_session_saves') > 1 THEN RAISE EXCEPTION 'unexpected repeated session write'; END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER recovery_second_save BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION recovery_second_save()").update();
			try {
				assertThat(post(client, PATH, session, body).statusCode()).isEqualTo(200);
				assertThat(this.jdbc.sql("SELECT last_value FROM recovery_session_saves").query(Long.class).single()).isEqualTo(1);
			}
			finally { this.jdbc.sql("DROP FUNCTION recovery_second_save() CASCADE").update(); this.jdbc.sql("DROP SEQUENCE recovery_session_saves").update(); }
		}
	}

	@Test
	void secretsStayOutOfSessionAuditAndDiagnosticText() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			for (String table : List.of("iam_security_audit", "iam_totp_recovery", "iam_password_authentication_limit", "iam_mfa_recovery_limit")) {
				assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t").query(String.class).list())
						.allSatisfy(row -> assertThat(row).doesNotContain(PASSWORD, oldCodes.codes().getFirst(), pending.token(), pending.enrollment().secret(), pending.enrollment().provisioningUri()));
			}
			assertThat(this.jdbc.sql("SELECT attribute_bytes FROM iam_browser_session_attributes").query(byte[].class).list())
					.allSatisfy(bytes -> assertThat(new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1)).doesNotContain(PASSWORD, oldCodes.codes().getFirst(), pending.token(), pending.enrollment().secret()));
			assertThat(new IdentityTotpRecoveryRequest(PASSWORD, oldCodes.codes().getFirst()).toString()).doesNotContain(PASSWORD, oldCodes.codes().getFirst());
			assertThat(new IdentityTotpRecoveryCompletionRequest(pending.recoveryId(), pending.token(), "123456").toString()).doesNotContain(pending.token(), "123456");
			assertThat(new IdentityTotpRecoveryResponse(pending.recoveryId(), pending.token(), pending.enrollment().factorId(), pending.enrollment().secret(), pending.enrollment().provisioningUri(), pending.enrollment().expiresAt()).toString())
					.doesNotContain(pending.token(), pending.enrollment().secret(), pending.enrollment().provisioningUri());
		}
	}

	@Test
	void anotherUsersRecoveryCodeCannotAuthorizeRecovery() throws Exception {
		UUID userId = activeUser("alice");
		UUID otherId = activeUser("bobby");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		var otherCodes = issueOldCodes(activeFactor(otherId));
		try (var client = client()) {
			String session = login(client, "alice");
			assertRejected(post(client, PATH, session, startBody(PASSWORD, otherCodes.codes().getFirst(), csrf(get(client, "/api/csrf", session)))), 400);
			assertThat(pendingCount()).isZero();
			assertThat(consumedCodeCount(userId)).isZero();
			assertThat(consumedCodeCount(otherId)).isZero();
			assertThat(begin(client, session, oldCodes).userId()).isEqualTo(userId);
		}
	}

	@Test
	void regeneratingTheOldCodeSetInvalidatesPendingRecoveryAndAllItsUnusedCodes() throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			var regeneration = post(client, "/api/me/mfa/recovery-codes", session, "code=" + freshTotp(old) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
			assertThat(regeneration.statusCode()).isEqualTo(200);
			List<String> codes = JsonPath.read(regeneration.body(), "$.codes");
			assertRejected(complete(client, session, pending), 400);
			assertRejected(post(client, PATH, session, startBody(PASSWORD, oldCodes.codes().get(1), csrf(get(client, "/api/csrf", session)))), 400);
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			assertThat(consumedCodeCount(userId)).isZero();
			assertThat(post(client, PATH, session, startBody(PASSWORD, codes.getFirst(), csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(200);
			assertThat(consumedCodeCount(userId)).isEqualTo(1);
			assertThat(events("totp_recovery_completed")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "recovery", "replacement" })
	void recoveryAndReplacementProofsCannotBeExchangedAndEitherCompletionInvalidatesTheOther(String completed) throws Exception {
		UUID userId = activeUser("alice");
		var old = activeFactor(userId);
		var oldCodes = issueOldCodes(old);
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			var replacement = beginReplacement(client, session, old);
			String csrf = csrf(get(client, "/api/csrf", session));
			var wrongRecovery = post(client, PATH + "/complete", session, "recoveryId=" + pending.recoveryId() + "&token=" + replacement.token() + "&code=" + otp(pending.enrollment(), step()) + "&_csrf=" + encode(csrf));
			assertRejected(wrongRecovery, 400);
			var wrongReplacement = post(client, "/api/me/mfa/totp/replacement/complete", session, "replacementId=" + replacement.replacementId() + "&token=" + pending.token() + "&code=" + otp(replacement.enrollment(), step()) + "&_csrf=" + encode(csrf));
			assertThat(wrongReplacement.statusCode()).isEqualTo(400);
			assertThat(wrongReplacement.body()).isEqualTo("TOTP replacement rejected");
			assertThat(factorId(userId)).isEqualTo(old.factorId());
			var result = completed.equals("recovery") ? complete(client, session, pending)
					: completeReplacement(client, session, replacement);
			assertThat(result.statusCode()).isEqualTo(200);
			assertThat(factorId(userId)).isEqualTo(completed.equals("recovery") ? pending.enrollment().factorId() : replacement.enrollment().factorId());
			assertThat(sessionCount(userId)).isZero();
			assertThat(pendingCount()).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_replacement").query(Long.class).single()).isZero();
			String nextSession = login(client, "alice");
			var stale = completed.equals("recovery") ? completeReplacement(client, nextSession, replacement) : complete(client, nextSession, pending);
			assertThat(stale.statusCode()).isEqualTo(400);
			assertThat(codeCount()).isEqualTo(10);
			assertThat(get(client, "/api/admin/me", nextSession).statusCode()).isEqualTo(403);
		}
	}

	@Test
	void concurrentStartsConsumeOneRecoveryCodeAndPublishOnePendingProof() throws Exception {
		UUID userId = activeUser("alice");
		var oldCodes = issueOldCodes(activeFactor(userId));
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = login(client, "alice");
			String body = startBody(PASSWORD, oldCodes.codes().getFirst(), csrf(get(client, "/api/csrf", session)));
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return post(client, PATH, session, body); });
			var second = executor.submit(() -> { start.await(); return post(client, PATH, session, body); });
			start.countDown();
			var responses = List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS));
			assertThat(responses.stream().map(HttpResponse::statusCode).toList()).containsExactlyInAnyOrder(200, 400);
			assertThat(consumedCodeCount(userId)).isEqualTo(1);
			assertThat(pendingCount()).isEqualTo(1);
			assertThat(events("totp_recovery_started")).isEqualTo(1);
			assertThat(sessionCount(userId)).isEqualTo(1);
		}
	}

	@Test
	void recoveryDoesNotDependOnDecryptingTheLostOldAuthenticator() throws Exception {
		UUID userId = activeUser("alice");
		var oldCodes = issueOldCodes(activeFactor(userId));
		this.jdbc.sql("UPDATE iam_user_totp SET key_id = repeat('0', 64)").update();
		try (var client = client()) {
			String session = login(client, "alice");
			var pending = begin(client, session, oldCodes);
			assertThat(complete(client, session, pending).statusCode()).isEqualTo(200);
			assertThat(sessionCount(userId)).isZero();
		}
	}

	@Test
	void anUnconfiguredProtectionKeyFailsBeforeConsumingTheRecoveryCode() throws Exception {
		UUID userId = activeUser("alice");
		var oldCodes = issueOldCodes(activeFactor(userId));
		try (var client = client()) {
			String session = login(client, "alice");
			String body = startBody(PASSWORD, oldCodes.codes().getFirst(), csrf(get(client, "/api/csrf", session)));
			var snapshot = snapshot(userId);
			try (var application = new SpringApplicationBuilder(IamApplication.class).properties(Map.of(
					"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
					"spring.datasource.password", this.postgres.getPassword(), "server.port", "0", "server.ssl.enabled", "true",
					"server.ssl.key-store", KEY_STORE.toUri().toString(), "server.ssl.key-store-password", "test-store-password",
					"spring.main.banner-mode", "off")).run("--iam.totp.key-file=")) {
				int unavailablePort = ((WebServerApplicationContext) application).getWebServer().getPort();
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + unavailablePort + PATH)).timeout(Duration.ofSeconds(20))
						.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
						.POST(HttpRequest.BodyPublishers.ofString(body)).build();
				assertUnavailable(client.send(request, HttpResponse.BodyHandlers.ofString()));
			}
			assertThat(snapshot(userId)).isEqualTo(snapshot);
			assertThat(consumedCodeCount(userId)).isZero();
			assertThat(pendingCount()).isZero();
			assertThat(events("totp_recovery_started")).isZero();
			assertThat(start(client, session, oldCodes).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void bothWorkflowsRejectCallerTransactions() {
		UUID userId = activeUser("alice");
		var transaction = new TransactionTemplate(this.transactions);
		assertThatThrownBy(() -> transaction.executeWithoutResult(status -> this.recoveries.begin(userId, "session", 1, System.currentTimeMillis(), PASSWORD, "recovery-code", recoveryContext(), () -> {}))).isInstanceOf(IllegalStateException.class).hasMessageContaining("independent transaction");
		assertThatThrownBy(() -> transaction.executeWithoutResult(status -> this.recoveries.complete(userId, "session", 1, System.currentTimeMillis(), UUID.randomUUID(), "token", "123456", context()))).isInstanceOf(IllegalStateException.class);
	}

	@TestConfiguration
	static class ConcurrentRequests implements WebMvcConfigurer {
		@Bean RequestPause requestPause() { return new RequestPause(); }
		@Override public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(requestPause()); }
	}

	static class RequestPause implements HandlerInterceptor {
		private CountDownLatch entered;
		private CountDownLatch release;
		private volatile boolean expirePassword;
		void start() { start(1); }
		void start(int requests) { this.entered = new CountDownLatch(requests); this.release = new CountDownLatch(1); this.expirePassword = false; }
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
	private IdentityTotpEnrollment activeFactor(UUID userId) {
		for (int attempt = 0; attempt < 10; attempt++) {
			var factor = this.totps.beginEnrollment(userId, SYSTEM);
			long step = step();
			if (Stream.of(step - 1, step, step + 1, step + 2).map(value -> otp(factor, value)).distinct().count() == 4) {
				this.jdbc.sql("UPDATE iam_user_totp SET status = 'active', activated_at = issued_at, last_used_step = :step WHERE user_id = :id").param("id", userId).param("step", step - 1).update();
				return factor;
			}
		}
		throw new AssertionError("Cannot create distinct adjacent TOTP codes for the fixture");
	}
	private String freshTotp(IdentityTotpEnrollment factor) { return otp(factor, Math.max(step(), lastUsedStep(factor.userId()) + 1)); }
	private MfaRecoveryCodeSet issueOldCodes(IdentityTotpEnrollment factor) { return this.recoveryCodes.issue(factor.userId(), freshTotp(factor), context()).orElseThrow(); }
	private String login(HttpClient client, String username) throws Exception {
		var anonymous = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(anonymous), credentials(username, PASSWORD, csrf(anonymous)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}

	private HttpResponse<String> start(HttpClient client, String session, MfaRecoveryCodeSet codes) throws Exception {
		return post(client, PATH, session, startBody(PASSWORD, codes.codes().getFirst(), csrf(get(client, "/api/csrf", session))));
	}
	private IdentityTotpRecovery begin(HttpClient client, String session, MfaRecoveryCodeSet codes) throws Exception {
		return begin(client, session, codes, 0);
	}
	private IdentityTotpRecovery begin(HttpClient client, String session, MfaRecoveryCodeSet codes, int codeIndex) throws Exception {
		var response = post(client, PATH, session, startBody(PASSWORD, codes.codes().get(codeIndex), csrf(get(client, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(200);
		assertSecurityHeaders(response);
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		Map<String, Object> result = JsonPath.read(response.body(), "$");
		assertThat(result).containsOnlyKeys("recoveryId", "token", "factorId", "secret", "provisioningUri", "expiresAt");
		return new IdentityTotpRecovery(codes.userId(), UUID.fromString(JsonPath.read(response.body(), "$.recoveryId")), JsonPath.read(response.body(), "$.token"),
				new IdentityTotpEnrollment(codes.userId(), UUID.fromString(JsonPath.read(response.body(), "$.factorId")), JsonPath.read(response.body(), "$.secret"), JsonPath.read(response.body(), "$.provisioningUri"), Instant.parse(JsonPath.read(response.body(), "$.expiresAt"))));
	}
	private HttpResponse<String> complete(HttpClient client, String session, IdentityTotpRecovery pending) throws Exception { return post(client, PATH + "/complete", session, completionBody(pending, csrf(get(client, "/api/csrf", session)))); }
	private IdentityTotpReplacement beginReplacement(HttpClient client, String session, IdentityTotpEnrollment old) throws Exception {
		var response = post(client, "/api/me/mfa/totp/replacement", session, "currentPassword=" + encode(PASSWORD) + "&code=" + freshTotp(old) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(200);
		return new IdentityTotpReplacement(old.userId(), UUID.fromString(JsonPath.read(response.body(), "$.replacementId")), JsonPath.read(response.body(), "$.token"),
				new IdentityTotpEnrollment(old.userId(), UUID.fromString(JsonPath.read(response.body(), "$.factorId")), JsonPath.read(response.body(), "$.secret"), JsonPath.read(response.body(), "$.provisioningUri"), Instant.parse(JsonPath.read(response.body(), "$.expiresAt"))));
	}
	private HttpResponse<String> completeReplacement(HttpClient client, String session, IdentityTotpReplacement pending) throws Exception {
		return post(client, "/api/me/mfa/totp/replacement/complete", session, "replacementId=" + pending.replacementId() + "&token=" + pending.token() + "&code=" + otp(pending.enrollment(), step()) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
	}
	private static String startBody(String password, String recoveryCode, String csrf) { return (password == null ? "" : "currentPassword=" + encode(password) + "&") + (recoveryCode == null ? "" : "recoveryCode=" + encode(recoveryCode) + "&") + "_csrf=" + encode(csrf); }
	private String completionBody(IdentityTotpRecovery pending, String csrf) { return "recoveryId=" + pending.recoveryId() + "&token=" + encode(pending.token()) + "&code=" + otp(pending.enrollment(), step()) + "&_csrf=" + encode(csrf); }
	private String base() { return "https://localhost:" + this.port + PATH; }
	private long step() { return this.jdbc.sql("SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::BIGINT").query(Long.class).single(); }
	private UUID factorId(UUID userId) { return this.jdbc.sql("SELECT factor_id FROM iam_user_totp WHERE user_id = :id").param("id", userId).query(UUID.class).single(); }
	private long lastUsedStep(UUID userId) { return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id = :id").param("id", userId).query(Long.class).single(); }
	private long version(UUID userId) { return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", userId).query(Long.class).single(); }
	private long codeCount() { return this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_code").query(Long.class).single(); }
	private long consumedCodeCount(UUID userId) { return this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_code WHERE user_id = :id AND consumed_at IS NOT NULL").param("id", userId).query(Long.class).single(); }
	private long pendingCount() { return this.jdbc.sql("SELECT count(*) FROM iam_totp_recovery").query(Long.class).single(); }
	private long sessionCount(UUID userId) { return this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", userId.toString()).query(Long.class).single(); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE source = :source AND action = :action").param("source", SOURCE).param("action", action).query(Long.class).single(); }
	private long failures(String budget, String dimension) { return this.jdbc.sql("SELECT COALESCE(sum(failures), 0) FROM " + (budget.equals("recovery") ? "iam_mfa_recovery_limit" : budget.equals("totp") ? "iam_totp_authentication_limit" : "iam_password_authentication_limit") + " WHERE dimension = :dimension").param("dimension", dimension).query(Long.class).single(); }
	private List<String> snapshot(UUID userId) {
		return List.of("iam_user_totp", "iam_totp_recovery", "iam_password", "iam_mfa_recovery_code").stream()
				.map(table -> this.jdbc.sql("SELECT COALESCE(string_agg(row_to_json(t)::text, ',' ORDER BY row_to_json(t)::text), '') FROM " + table + " t WHERE user_id = :id").param("id", userId).query(String.class).single()).toList();
	}
	private Object attribute(String cookie, String name) {
		return this.jdbc.sql("SELECT a.attribute_bytes FROM iam_browser_session_attributes a JOIN iam_browser_session s ON s.primary_id = a.session_primary_id WHERE s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).query(byte[].class).optional().map(SerializationUtils::deserialize).orElse(null);
	}
	private void setAttribute(String cookie, String name, Object value) {
		assertThat(this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update()).isEqualTo(1);
	}
	private void awaitBlocked(int pid) { await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))").param("pid", pid).query(Boolean.class).single()); }
	private static void assertRejected(HttpResponse<String> response, int status) { assertThat(response.statusCode()).isEqualTo(status); assertSecurityHeaders(response); assertThat(response.body()).isEqualTo(status == 429 ? "Verification temporarily unavailable" : "TOTP recovery rejected"); }
	private static void assertUnavailable(HttpResponse<String> response) { assertThat(response.statusCode()).isEqualTo(503); assertSecurityHeaders(response); assertThat(response.body()).contains("SERVICE_UNAVAILABLE").doesNotContain("secret", "codes", "token", "injected", "SQL", PASSWORD); assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); }
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static MfaRecoveryCodeContext recoveryContext() { return new MfaRecoveryCodeContext("internal:test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try { Path path = Files.createTempFile("iam-totp-recovery-http-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key); Files.write(path, key); path.toFile().deleteOnExit(); return path; }
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String otp(IdentityTotpEnrollment factor, long step) {
		byte[] counter = new byte[8]; for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(factor.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(java.util.Locale.ROOT, "%06d", number % 1_000_000);
	}

}
