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
import com.ixayda.iam.dto.IdentityTotpEnrollmentConfirmationRequest;
import com.ixayda.iam.dto.IdentityTotpEnrollmentRequest;
import com.ixayda.iam.dto.IdentityTotpEnrollmentResponse;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityMfaRecoveryCodes;
import com.ixayda.iam.service.IdentityTotpEnrollments;
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
@Import({ PostgreSqlTestConfiguration.class, IdentityTotpEnrollmentControllerIntegrationTests.ConcurrentRequests.class })
class IdentityTotpEnrollmentControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/me/mfa/totp/enrollment";
	private static final String SOURCE = "browser:totp-enrollment";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:enrollment-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityTotpEnrollments enrollments;
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
	void aPasswordSessionCanEnrollAndReceiveItsFirstRecoveryCodesWithoutGainingManagementPermission() throws Exception {
		UUID userId = activeUser("alice");
		UUID otherId = activeUser("bobby");
		try (var client = client()) {
			String session = login(client, "alice");
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			var enrollment = begin(client, session, userId);
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isEqualTo(enrollment.factorId());
			assertThat(enrollment.secret()).matches("[A-Z2-7]{32}");
			assertThat(enrollment.provisioningUri()).contains("otpauth://totp/IAM:" + userId, "secret=" + enrollment.secret(), "issuer=IAM", "algorithm=SHA1", "digits=6", "period=30");
			assertThat(enrollment.expiresAt()).isBetween(Instant.now().plusSeconds(590), Instant.now().plusSeconds(601));
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(codeCount()).isZero();
			String confirmingCode = otp(enrollment);
			var response = post(client, PATH + "/confirm", session, "factorId=" + enrollment.factorId() + "&code=" + confirmingCode + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
			assertThat(response.statusCode()).isEqualTo(200);
			assertSecurityHeaders(response);
			assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
			Map<String, Object> body = JsonPath.read(response.body(), "$");
			assertThat(body).containsOnlyKeys("generationId", "codes", "issuedAt");
			List<String> codes = JsonPath.read(response.body(), "$.codes");
			assertThat(codes).hasSize(10).doesNotHaveDuplicates().allMatch(code -> code.matches("[0-9a-f]{4}(-[0-9a-f]{4}){7}"));
			assertThat(factorState(userId)).isEqualTo("active");
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isNull();
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isNull();
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(403);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp WHERE user_id = :id").param("id", otherId).query(Long.class).single()).isZero();
			assertThat(this.totps.verify(userId, confirmingCode, context())).isEmpty();
			var recoveryContext = new MfaRecoveryCodeContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID());
			assertThat(this.recoveryCodes.consume(userId, codes.getFirst(), recoveryContext)).isPresent();
			assertThat(this.recoveryCodes.consume(userId, codes.getFirst(), recoveryContext)).isEmpty();
			String storage = this.jdbc.sql("SELECT secret_ciphertext FROM iam_user_totp WHERE user_id = :id").param("id", userId).query(String.class).single();
			assertThat(storage).doesNotContain(enrollment.secret(), enrollment.provisioningUri());
			String digests = this.jdbc.sql("SELECT string_agg(code_digest, ',') FROM iam_mfa_recovery_code").query(String.class).single();
			for (String code : codes) { assertThat(digests).doesNotContain(code); }
			assertThat(response.body()).doesNotContain(enrollment.secret(), "userId", "factorId", "credentialVersion", PASSWORD);
			assertThat(events("totp_enrollment_started")).isEqualTo(1);
			assertThat(events("password_authenticated")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT count(DISTINCT correlation_id) FROM iam_security_audit WHERE source = :source AND action IN ('password_authenticated', 'totp_enrollment_started')").param("source", SOURCE).query(Long.class).single()).isEqualTo(1);
			assertThat(events("totp_enrollment_completed")).isEqualTo(1);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT count(DISTINCT correlation_id) FROM iam_security_audit WHERE source = :source AND action IN ('totp_enrollment_completed', 'mfa_recovery_codes_generated')").param("source", SOURCE).query(Long.class).single()).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE source = :source").param("source", SOURCE).query(String.class).list()).containsOnly("user:" + userId);
			assertThat(this.jdbc.sql("SELECT attribute_bytes FROM iam_browser_session_attributes").query(byte[].class).list())
					.allSatisfy(bytes -> assertThat(new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1)).doesNotContain(PASSWORD, enrollment.secret(), enrollment.provisioningUri()));
			for (String table : List.of("iam_security_audit", "iam_password_authentication_limit")) {
				assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t").query(String.class).list())
						.allSatisfy(row -> assertThat(row).doesNotContain(PASSWORD, enrollment.secret(), enrollment.provisioningUri()));
			}
		}
	}

	@ParameterizedTest
	@CsvSource({ "0, missing", "7200000, missing", "7200000, empty", "7200000, wrong" })
	void aValidPasswordSessionStillRequiresTheCurrentPasswordForEnrollment(long sessionAge, String supplied) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			long passwordTime = System.currentTimeMillis() - sessionAge;
			setAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			String password = supplied.equals("missing") ? null : supplied.equals("empty") ? "" : "incorrect password";
			var denied = post(client, PATH, session, enrollment(password, csrf(get(client, "/api/csrf", session))));
			assertRejected(denied, 400);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isNull();
			assertThat(codeCount()).isZero();
			assertThat(events("totp_enrollment_started")).isZero();
			assertThat(events("password_authenticated")).isZero();
			assertThat(events("password_auth_failed")).isEqualTo(1);
			assertThat(passwordFailures("account")).isEqualTo(1);
			assertThat(passwordFailures("source")).isEqualTo(1);
			assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE source = :source AND action = 'password_auth_failed'").param("source", SOURCE).query(String.class).single()).isEqualTo("anonymous");
			assertThat(this.jdbc.sql("SELECT target_user_id FROM iam_security_audit WHERE source = :source AND action = 'password_auth_failed'").param("source", SOURCE).query(UUID.class).single()).isEqualTo(userId);
			var enrollment = begin(client, session, userId);
			assertThat(confirm(client, session, enrollment).statusCode()).isEqualTo(200);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(passwordFailures("account")).isZero();
			assertThat(passwordFailures("source")).isEqualTo(1);
		}
	}

	@Test
	void aPasswordHeaderCannotSupplyAMissingPasswordOrOverrideAnIncorrectBody() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			for (String fields : List.of("", "currentPassword=wrong")) {
				var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
						.header("X-CSRF-TOKEN", token).header("currentPassword", PASSWORD).POST(HttpRequest.BodyPublishers.ofString(fields)).build();
				assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 400);
			}
			assertThat(events("password_auth_failed")).isEqualTo(2);
			assertThat(events("totp_enrollment_started")).isZero();
			assertThat(passwordFailures("account")).isEqualTo(2);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
		}
	}

	@Test
	void aFailedPasswordRecheckCannotReplaceAnExistingEnrollment() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var original = begin(client, session, userId);
			assertRejected(post(client, PATH, session, enrollment("wrong", csrf(get(client, "/api/csrf", session)))), 400);
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isEqualTo(original.factorId());
			assertThat(events("totp_enrollment_started")).isEqualTo(1);
			assertThat(confirm(client, session, original).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void passwordAccountFailuresAreSharedWithLoginAndThrottlingCannotBeBypassedWithTheCorrectPassword() throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String token = csrf(get(client, "/api/csrf", session));
			for (int i = 0; i < 5; i++) { assertRejected(post(client, PATH, session, enrollment("wrong", token)), 400); }
			var anonymous = get(client, "/api/csrf", null);
			for (int i = 0; i < 5; i++) { assertThat(post(client, "/login", cookie(anonymous), credentials("alice", "wrong", csrf(anonymous))).statusCode()).isEqualTo(401); }
			assertRejected(post(client, PATH, session, enrollment(PASSWORD, token)), 429);
			assertThat(post(client, "/login", cookie(anonymous), credentials("alice", PASSWORD, csrf(anonymous))).statusCode()).isEqualTo(401);
			assertThat(passwordFailures("account")).isEqualTo(10);
			assertThat(passwordFailures("source")).isEqualTo(10);
			assertThat(events("password_auth_failed")).isEqualTo(5);
			assertThat(events("password_auth_throttled")).isEqualTo(1);
			assertThat(events("totp_enrollment_started")).isZero();
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isNull();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void passwordSourceThrottlingAppliesAcrossUsersAndIgnoresForwardedHeaders() throws Exception {
		activeUser("alice");
		activeUser("bobby");
		try (var client = client()) {
			String alice = login(client, "alice");
			String bobby = login(client, "bobby");
			var accounts = this.jdbc.sql("SELECT row_to_json(t)::text FROM iam_password_authentication_limit t WHERE dimension = 'account' ORDER BY subject_key").query(String.class).list();
			this.jdbc.sql("UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'").update();
			for (String session : List.of(alice, bobby)) {
				var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
						.header("X-Forwarded-For", "192.0.2.90").header("Forwarded", "for=192.0.2.90")
						.POST(HttpRequest.BodyPublishers.ofString(enrollment(PASSWORD, csrf(get(client, "/api/csrf", session))))).build();
				assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 429);
			}
			assertThat(passwordFailures("source")).isEqualTo(50);
			assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM iam_password_authentication_limit t WHERE dimension = 'account' ORDER BY subject_key").query(String.class).list()).isEqualTo(accounts);
			assertThat(events("password_auth_throttled")).isEqualTo(2);
			assertThat(events("password_authenticated")).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
		}
	}

	@Test
	void restartingEnrollmentReplacesTheSecretAndOldOperationsCannotAffectTheNewFactor() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var old = begin(client, session, userId);
			var current = begin(client, session, userId);
			assertThat(current.factorId()).isNotEqualTo(old.factorId());
			assertThat(current.secret()).isNotEqualTo(old.secret());
			assertRejected(confirm(client, session, old), 400);
			assertRejected(cancel(client, session, old.factorId()), 400);
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isEqualTo(current.factorId());
			assertThat(confirm(client, session, current).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "same-user", "other-user" })
	void anotherSessionCannotConfirmOrCancelAnEnrollmentEvenWithItsIdAndValidCode(String owner) throws Exception {
		UUID userId = activeUser("alice");
		activeUser("bobby");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String other = login(client, owner.equals("same-user") ? "alice" : "bobby");
			assertRejected(confirm(client, other, enrollment), 400);
			assertRejected(cancel(client, other, enrollment.factorId()), 400);
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(confirm(client, session, enrollment).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void anotherSessionStartingAgainInvalidatesTheOriginalSessionEnrollment() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String first = login(client, "alice");
			String second = login(client, "alice");
			var old = begin(client, first, userId);
			var current = begin(client, second, userId);
			assertRejected(confirm(client, first, old), 400);
			assertRejected(cancel(client, first, old.factorId()), 400);
			assertThat(confirm(client, second, current).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void activeFactorsCannotBeReenrolledCancelledOrConfirmedAgain() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			assertThat(confirm(client, session, enrollment).statusCode()).isEqualTo(200);
			assertRejected(start(client, session), 400);
			assertRejected(cancel(client, session, enrollment.factorId()), 400);
			assertRejected(confirm(client, session, enrollment), 400);
			assertThat(factorState(userId)).isEqualTo("active");
			assertThat(codeCount()).isEqualTo(10);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
		}
	}

	@Test
	void expiredPendingEnrollmentCannotActivateButCanBeCancelled() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			this.jdbc.sql("UPDATE iam_user_totp SET issued_at = clock_timestamp() - INTERVAL '11 minutes', expires_at = clock_timestamp() - INTERVAL '1 second'").update();
			assertRejected(confirm(client, session, enrollment), 400);
			var response = cancel(client, session, enrollment.factorId());
			assertThat(response.statusCode()).isEqualTo(204);
			assertThat(response.body()).isEmpty();
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isNull();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
			assertThat(events("totp_enrollment_cancelled")).isEqualTo(1);
			assertThat(codeCount()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "1", "12345", "1234567", "abcdef", "１２３４５６", "123%20456", "%20123456", "123456%0A" })
	void malformedCodesConsumeTheSharedFailureBudgetWithoutActivating(String code) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			assertRejected(post(client, PATH + "/confirm", session, "factorId=" + enrollment.factorId() + "&code=" + code + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session)))), 400);
			assertThat(failures()).isEqualTo(1);
			assertThat(events("totp_enrollment_failed")).isEqualTo(1);
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(codeCount()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "code", "factorId", "both" })
	void requestHeadersCannotSupplyMissingBusinessFields(String header) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String body = header.equals("code") ? "factorId=" + enrollment.factorId() : header.equals("factorId") ? "code=" + otp(enrollment) : "";
			var request = HttpRequest.newBuilder(URI.create(base() + "/confirm")).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session))).header("code", otp(enrollment)).header("factorId", enrollment.factorId().toString())
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 400);
			assertThat(failures()).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "/confirm", "/cancel" })
	void csrfMediaTypeQueriesExtraFieldsAndDuplicatesAreRejectedBeforeBusinessChanges(String suffix) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			String fields = suffix.isEmpty() ? "currentPassword=" + encode(PASSWORD) : "factorId=" + enrollment.factorId() + (suffix.equals("/confirm") ? "&code=" + otp(enrollment) : "");
			String body = fields + (fields.isEmpty() ? "" : "&") + "_csrf=" + encode(token);
			assertThat(post(client, PATH + suffix, session, fields).statusCode()).isEqualTo(403);
			assertThat(post(client, PATH + suffix + "?unexpected=true", session, body).statusCode()).isEqualTo(400);
			for (String extra : List.of("userId=" + userId, "source=forged", "actor=forged", "_csrf=" + encode(token), "factorId=" + enrollment.factorId(), "currentPassword=" + encode(PASSWORD))) {
				assertThat(post(client, PATH + suffix, session, body + "&" + extra).statusCode()).isEqualTo(400);
			}
			var json = HttpRequest.newBuilder(URI.create(base() + suffix)).header("Cookie", session).header("X-CSRF-TOKEN", token)
					.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			var unacceptable = HttpRequest.newBuilder(URI.create(base() + suffix)).header("Cookie", session).header("Accept", "text/html")
					.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build();
			assertThat(client.send(unacceptable, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(406);
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(events("totp_enrollment_started")).isEqualTo(1);
			assertThat(events("totp_enrollment_cancelled")).isZero();
			assertThat(codeCount()).isZero();
			assertThat(failures()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "/confirm", "/cancel" })
	void anonymousRequestsAndMethodsOtherThanPostAreDenied(String suffix) throws Exception {
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
			assertThat(events("totp_enrollment_started")).isZero();
		}
	}

	@Test
	void csrfHeadersAreAcceptedWithTheCurrentPasswordInTheBody() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var request = HttpRequest.newBuilder(URI.create(base())).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-CSRF-TOKEN", csrf(get(client, "/api/csrf", session))).POST(HttpRequest.BodyPublishers.ofString("currentPassword=" + encode(PASSWORD))).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
			assertThat(factorState(userId)).isEqualTo("pending");
		}
	}

	@Test
	void accountBudgetIsSharedWithOtherTotpVerificationAndNotResetByRestartingEnrollment() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			begin(client, session, userId);
			for (int i = 0; i < 5; i++) { assertThat(this.totps.verify(userId, "bad", context())).isEmpty(); }
			var current = begin(client, session, userId);
			assertRejected(confirm(client, session, current), 429);
			assertThat(failures()).isEqualTo(5);
			assertThat(events("totp_enrollment_throttled")).isEqualTo(1);
			assertThat(factorState(userId)).isEqualTo("pending");
		}
	}

	@Test
	void sourceBudgetIsSharedAcrossUsersAndForwardedHeadersCannotBypassIt() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			for (int i = 0; i < 30; i++) { assertThat(this.totps.verify(UUID.randomUUID(), "bad", context())).isEmpty(); }
			var request = HttpRequest.newBuilder(URI.create(base() + "/confirm")).header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Forwarded-For", "192.0.2.90").header("Forwarded", "for=192.0.2.90")
					.POST(HttpRequest.BodyPublishers.ofString(confirmation(enrollment, csrf(get(client, "/api/csrf", session))))).build();
			assertRejected(client.send(request, HttpResponse.BodyHandlers.ofString()), 429);
			assertThat(codeCount()).isZero();
		}
	}

	@Test
	void concurrentConfirmationCommitsOneActivationAndOneRecoverySet() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String body = confirmation(enrollment, csrf(get(client, "/api/csrf", session)));
			var start = new CountDownLatch(1);
			var first = executor.submit(() -> { start.await(); return post(client, PATH + "/confirm", session, body); });
			var second = executor.submit(() -> { start.await(); return post(client, PATH + "/confirm", session, body); });
			start.countDown();
			assertThat(List.of(first.get(20, TimeUnit.SECONDS).statusCode(), second.get(20, TimeUnit.SECONDS).statusCode())).containsExactlyInAnyOrder(200, 400);
			assertThat(events("totp_enrollment_completed")).isEqualTo(1);
			assertThat(events("mfa_recovery_codes_generated")).isEqualTo(1);
			assertThat(codeCount()).isEqualTo(10);
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, version", "begin, disabled", "begin, session", "begin, password-expiry",
			"confirm, version", "confirm, disabled", "confirm, session", "confirm, password-expiry",
			"cancel, version", "cancel, disabled", "cancel, session", "cancel, password-expiry" })
	void changedAuthenticationIsRecheckedAfterHttpAuthorization(String operation, String change) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			String body = operation.equals("begin") ? enrollment(PASSWORD, token) : operation.equals("confirm") ? confirmation(enrollment, token) : cancellation(enrollment.factorId(), token);
			this.pause.start();
			var request = HttpRequest.newBuilder(URI.create(base() + (operation.equals("begin") ? "" : "/" + operation)))
					.header("Cookie", session).header("Content-Type", "application/x-www-form-urlencoded").header("X-Test-Pause", "true")
					.POST(HttpRequest.BodyPublishers.ofString(body)).build();
			var waiting = executor.submit(() -> client.send(request, HttpResponse.BodyHandlers.ofString()));
			try {
				assertThat(this.pause.entered.await(10, TimeUnit.SECONDS)).isTrue();
				if (change.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
				else if (change.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled'").update(); }
				else if (change.equals("password-expiry")) { this.pause.expirePassword = true; }
				else { this.jdbc.sql("DELETE FROM iam_browser_session").update(); }
			}
			finally { this.pause.release.countDown(); }
			assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(401);
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(events("totp_enrollment_started")).isEqualTo(1);
			assertThat(events("totp_enrollment_cancelled")).isZero();
			assertThat(codeCount()).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, factor, error", "begin, factor, silent", "begin, factor, deferred", "begin, audit, error", "begin, audit, silent", "begin, audit, deferred", "begin, password-audit, error", "begin, password-audit, silent", "begin, password-audit, deferred", "begin, session, error", "begin, session, silent", "begin, session, deferred", "begin, attribute, error", "begin, attribute, silent", "begin, attribute, deferred",
			"confirm, factor, error", "confirm, factor, silent", "confirm, factor, deferred", "confirm, codes, error", "confirm, codes, silent", "confirm, codes, deferred", "confirm, audit, error", "confirm, audit, silent", "confirm, audit, deferred", "confirm, factor-audit, error", "confirm, factor-audit, silent", "confirm, factor-audit, deferred", "confirm, session, error", "confirm, session, silent", "confirm, session, deferred", "confirm, attribute, error", "confirm, attribute, silent", "confirm, attribute, deferred",
			"cancel, factor, error", "cancel, factor, silent", "cancel, factor, deferred", "cancel, audit, error", "cancel, audit, silent", "cancel, audit, deferred", "cancel, session, error", "cancel, session, silent", "cancel, session, deferred", "cancel, attribute, error", "cancel, attribute, silent", "cancel, attribute, deferred" })
	void persistenceAuditAndCommitFaultsRollbackTheWholeWorkflow(String operation, String target, String mode) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = operation.equals("begin") ? null : begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			if (operation.equals("begin")) { assertRejected(post(client, PATH, session, enrollment("wrong", token)), 400); }
			String body = operation.equals("begin") ? enrollment(PASSWORD, token) : operation.equals("confirm") ? confirmation(enrollment, token) : cancellation(enrollment.factorId(), token);
			String table = target.equals("factor") ? "iam_user_totp" : target.equals("codes") ? "iam_mfa_recovery_code" : target.equals("session") ? "iam_browser_session" : target.equals("attribute") ? "iam_browser_session_attributes" : "iam_security_audit";
			String event = target.equals("password-audit") ? "password_authenticated" : operation.equals("begin") ? "totp_enrollment_started" : operation.equals("cancel") ? "totp_enrollment_cancelled" : target.equals("factor-audit") ? "totp_enrollment_completed" : "mfa_recovery_codes_generated";
			String sqlOperation = target.equals("session") ? "UPDATE" : target.equals("attribute") ? (operation.equals("begin") ? "INSERT" : "DELETE") : target.equals("factor") ? (operation.equals("begin") ? "INSERT" : operation.equals("confirm") ? "UPDATE" : "DELETE") : "INSERT";
			String row = sqlOperation.equals("DELETE") ? "OLD" : "NEW";
			String guard = target.contains("audit") ? "IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + event + "' THEN RETURN NEW; END IF; " : target.equals("attribute") ? "IF " + row + ".attribute_name <> '" + IdentityBrowserSessions.TOTP_ENROLLMENT + "' THEN RETURN " + row + "; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION enrollment_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected enrollment failure';") + " END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER enrollment_fault AFTER " : "CREATE TRIGGER enrollment_fault BEFORE ") + sqlOperation + " ON " + table + (mode.equals("deferred") ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION enrollment_fault()").update();
			try { assertUnavailable(post(client, PATH + (operation.equals("begin") ? "" : "/" + operation), session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION enrollment_fault() CASCADE").update(); }
			assertThat(codeCount()).isZero();
			assertThat(events("totp_enrollment_completed")).isZero();
			assertThat(events("totp_enrollment_cancelled")).isZero();
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
			if (enrollment == null) {
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
				assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isNull();
				assertThat(events("totp_enrollment_started")).isZero();
				assertThat(events("password_authenticated")).isZero();
				assertThat(passwordFailures("account")).isEqualTo(1);
				assertThat(passwordFailures("source")).isEqualTo(1);
			}
			else {
				assertThat(factorState(userId)).isEqualTo("pending");
				assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isEqualTo(enrollment.factorId());
				assertThat(confirm(client, session, enrollment).statusCode()).isEqualTo(200);
			}
		}
	}

	@ParameterizedTest
	@CsvSource({ "begin, error", "begin, silent", "begin, deferred", "confirm, error", "confirm, silent", "confirm, deferred" })
	void failureAuditFaultsDoNotConsumeFailureBudgets(String operation, String mode) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			String body = operation.equals("begin") ? enrollment("wrong", token) : "factorId=" + enrollment.factorId() + "&code=bad&_csrf=" + encode(token);
			String action = operation.equals("begin") ? "password_auth_failed" : "totp_enrollment_failed";
			this.jdbc.sql("CREATE FUNCTION enrollment_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source = '" + SOURCE + "' AND NEW.action = '" + action + "' THEN " + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected failure audit fault';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER enrollment_denial_fault AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER enrollment_denial_fault BEFORE INSERT ON iam_security_audit") + " FOR EACH ROW EXECUTE FUNCTION enrollment_denial_fault()").update();
			try { assertUnavailable(post(client, PATH + (operation.equals("begin") ? "" : "/confirm"), session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION enrollment_denial_fault() CASCADE").update(); }
			assertThat(failures()).isZero();
			assertThat(passwordFailures("account")).isZero();
			assertThat(passwordFailures("source")).isZero();
			assertThat(events(action)).isZero();
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isEqualTo(enrollment.factorId());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent", "deferred" })
	void passwordThrottlingAuditFaultsRejectEnrollmentWithoutPublishingSecrets(String mode) throws Exception {
		activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			String body = enrollment(PASSWORD, csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'").update();
			this.jdbc.sql("CREATE FUNCTION enrollment_throttle_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source = '" + SOURCE + "' AND NEW.action = 'password_auth_throttled' THEN " + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected throttling audit fault';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER enrollment_throttle_fault AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER enrollment_throttle_fault BEFORE INSERT ON iam_security_audit") + " FOR EACH ROW EXECUTE FUNCTION enrollment_throttle_fault()").update();
			try { assertUnavailable(post(client, PATH, session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION enrollment_throttle_fault() CASCADE").update(); }
			assertThat(passwordFailures("source")).isEqualTo(50);
			assertThat(events("password_auth_throttled")).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isNull();
		}
	}

	@ParameterizedTest
	@CsvSource({ "confirm, user", "confirm, session", "begin, user", "begin, session", "begin, source", "begin, account" })
	void idleExpiryWhileWaitingForLocksPreventsEnrollmentChanges(String operation, String locked) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			if (operation.equals("begin")) { assertRejected(post(client, PATH, session, enrollment("wrong", token)), 400); }
			String body = operation.equals("begin") ? enrollment(PASSWORD, token) : confirmation(enrollment, token);
			long deadline = System.currentTimeMillis() + 2000;
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :deadline").param("deadline", deadline).update();
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			String lockingSql = locked.equals("user") ? "SELECT id FROM iam_user WHERE id = ? FOR UPDATE" : locked.equals("session") ? "SELECT session_id FROM iam_browser_session WHERE session_id = ? FOR UPDATE" : "SELECT subject_key FROM iam_password_authentication_limit WHERE dimension = ? FOR UPDATE";
			try (var statement = blocker.prepareStatement(lockingSql)) {
				statement.setObject(1, locked.equals("user") ? userId : locked.equals("session") ? session.substring(session.indexOf('=') + 1) : locked); statement.executeQuery().close();
			}
			var waiting = executor.submit(() -> post(client, PATH + (operation.equals("begin") ? "" : "/confirm"), session, body));
			try {
				awaitBlocked(pid);
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertThat(waiting.get(15, TimeUnit.SECONDS).statusCode()).isEqualTo(401);
			}
			finally { blocker.rollback(); }
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(codeCount()).isZero();
			assertThat(events("totp_enrollment_started")).isEqualTo(1);
			assertThat(events("password_authenticated")).isEqualTo(1);
		}
	}

	@Test
	void callerTransactionsAreRejectedAndSensitiveTextIsRedacted() {
		UUID userId = activeUser("alice");
		var transaction = new TransactionTemplate(this.transactions);
		assertThatThrownBy(() -> transaction.executeWithoutResult(status -> this.enrollments.begin(userId, "session", 1, System.currentTimeMillis(), PASSWORD, passwordContext(), factor -> {}))).isInstanceOf(IllegalStateException.class).hasMessageContaining("independent transaction");
		assertThatThrownBy(() -> transaction.executeWithoutResult(status -> this.enrollments.confirm(userId, "session", 1, System.currentTimeMillis(), null, null, "123456", context(), factor -> {}))).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> transaction.executeWithoutResult(status -> this.enrollments.cancel(userId, "session", 1, System.currentTimeMillis(), null, null, SYSTEM, factor -> {}))).isInstanceOf(IllegalStateException.class);
		assertThat(new IdentityTotpEnrollmentRequest(PASSWORD).toString()).doesNotContain(PASSWORD);
		assertThat(new IdentityTotpEnrollmentConfirmationRequest(UUID.randomUUID(), "123456").toString()).doesNotContain("123456");
		assertThat(new IdentityTotpEnrollmentResponse(UUID.randomUUID(), "sensitive-secret", "otpauth://sensitive-uri", Instant.now()).toString()).doesNotContain("sensitive-secret", "sensitive-uri");
	}

	@ParameterizedTest
	@CsvSource({ "password, begin, factor", "password, begin, audit", "password, begin, password-audit", "password, begin, session",
			"password, confirm, factor", "password, confirm, codes", "password, confirm, audit", "password, confirm, session",
			"password, cancel, factor", "password, cancel, audit", "password, cancel, session",
			"idle, begin, factor", "idle, begin, audit", "idle, begin, password-audit", "idle, begin, session",
			"idle, confirm, factor", "idle, confirm, codes", "idle, confirm, audit", "idle, confirm, session",
			"idle, cancel, factor", "idle, cancel, audit", "idle, cancel, session",
			"enrollment, begin, session", "enrollment, confirm, codes", "enrollment, confirm, audit", "enrollment, confirm, session" })
	void expirationDuringPersistenceRollsBackChangesAndDoesNotPublishSecrets(String expiration, String operation, String waitingAt) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client(); var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()); var executor = Executors.newSingleThreadExecutor()) {
			String session = login(client, "alice");
			var enrollment = operation.equals("begin") ? null : begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			String body = operation.equals("begin") ? enrollment(PASSWORD, token) : operation.equals("confirm") ? confirmation(enrollment, token) : cancellation(enrollment.factorId(), token);
			long deadline = System.currentTimeMillis() + 2500;
			if (expiration.equals("password")) {
				this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
						.param("id", session.substring(session.indexOf('=') + 1)).param("name", IdentityBrowserSessions.AUTHENTICATED_AT).param("value", SerializationUtils.serialize(deadline - 28_800_000)).update();
			}
			else if (expiration.equals("idle")) {
				this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
						.param("expiry", deadline).param("id", session.substring(session.indexOf('=') + 1)).update();
			}
			else if (enrollment != null) {
				this.jdbc.sql("UPDATE iam_user_totp SET issued_at = clock_timestamp() - INTERVAL '10 minutes', expires_at = to_timestamp(:deadline / 1000.0)").param("deadline", deadline).update();
			}
			blocker.setAutoCommit(false);
			int pid;
			try (var statement = blocker.createStatement(); var row = statement.executeQuery("SELECT pg_backend_pid()")) { row.next(); pid = row.getInt(1); }
			try (var statement = blocker.createStatement()) { statement.execute("SELECT pg_advisory_xact_lock(72173843)"); }
			// Test-only shortening of a newly issued enrollment lets the final check see real database expiry.
			if (expiration.equals("enrollment") && operation.equals("begin")) {
				this.jdbc.sql("CREATE FUNCTION enrollment_deadline() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source = '" + SOURCE + "' AND NEW.action = 'totp_enrollment_started' THEN UPDATE iam_user_totp SET issued_at = clock_timestamp() - INTERVAL '10 minutes', expires_at = to_timestamp(" + deadline + " / 1000.0); END IF; RETURN NEW; END $$").update();
				this.jdbc.sql("CREATE TRIGGER enrollment_deadline BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION enrollment_deadline()").update();
			}
			String table = waitingAt.equals("factor") ? "iam_user_totp" : waitingAt.equals("codes") ? "iam_mfa_recovery_code" : waitingAt.endsWith("audit") ? "iam_security_audit" : "iam_browser_session";
			String sqlOperation = waitingAt.equals("session") ? "UPDATE" : waitingAt.equals("factor") ? (operation.equals("begin") ? "INSERT" : operation.equals("cancel") ? "DELETE" : "UPDATE") : "INSERT";
			String auditAction = waitingAt.equals("password-audit") ? "password_authenticated" : operation.equals("begin") ? "totp_enrollment_started" : operation.equals("cancel") ? "totp_enrollment_cancelled" : "mfa_recovery_codes_generated";
			String guard = waitingAt.endsWith("audit") ? "IF NEW.source <> '" + SOURCE + "' OR NEW.action <> '" + auditAction + "' THEN RETURN NEW; END IF; " : "";
			this.jdbc.sql("CREATE FUNCTION enrollment_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + guard + "PERFORM pg_advisory_xact_lock(72173843); RETURN " + (sqlOperation.equals("DELETE") ? "OLD" : "NEW") + "; END $$").update();
			this.jdbc.sql("CREATE TRIGGER enrollment_wait BEFORE " + sqlOperation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION enrollment_wait()").update();
			var waiting = executor.submit(() -> post(client, PATH + (operation.equals("begin") ? "" : "/" + operation), session, body));
			try {
				awaitBlocked(pid);
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertUnavailable(waiting.get(15, TimeUnit.SECONDS));
			}
			finally {
				blocker.rollback();
				this.jdbc.sql("DROP FUNCTION enrollment_wait() CASCADE").update();
				if (expiration.equals("enrollment") && operation.equals("begin")) { this.jdbc.sql("DROP FUNCTION enrollment_deadline() CASCADE").update(); }
			}
			assertThat(codeCount()).isZero();
			assertThat(events("totp_enrollment_completed")).isZero();
			assertThat(events("totp_enrollment_cancelled")).isZero();
			assertThat(events("mfa_recovery_codes_generated")).isZero();
			if (enrollment == null) {
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
				assertThat(events("password_authenticated")).isZero();
			}
			else { assertThat(factorState(userId)).isEqualTo("pending"); }
			if (expiration.equals("idle")) {
				assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(401);
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE session_id = :id")
						.param("id", session.substring(session.indexOf('=') + 1)).query(Long.class).single()).isZero();
			}
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT))
					.isEqualTo(enrollment == null || expiration.equals("idle") ? null : enrollment.factorId());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "begin", "confirm", "cancel" })
	void anUnchangedSessionIsNotSavedAgainByTheRequestFinalizer(String operation) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = operation.equals("begin") ? null : begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			String body = operation.equals("begin") ? enrollment(PASSWORD, token) : operation.equals("confirm") ? confirmation(enrollment, token) : cancellation(enrollment.factorId(), token);
			this.jdbc.sql("CREATE SEQUENCE enrollment_session_saves").update();
			this.jdbc.sql("CREATE FUNCTION enrollment_second_save() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('enrollment_session_saves') > 1 THEN RAISE EXCEPTION 'unexpected repeated session write'; END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER enrollment_second_save BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION enrollment_second_save()").update();
			try {
				assertThat(post(client, PATH + (operation.equals("begin") ? "" : "/" + operation), session, body).statusCode()).isEqualTo(operation.equals("cancel") ? 204 : 200);
				assertThat(this.jdbc.sql("SELECT last_value FROM enrollment_session_saves").query(Long.class).single()).isEqualTo(1);
			}
			finally { this.jdbc.sql("DROP FUNCTION enrollment_second_save() CASCADE").update(); this.jdbc.sql("DROP SEQUENCE enrollment_session_saves").update(); }
			assertThat(get(client, "/api/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void loggingInAgainCannotInheritTheOldEnrollmentBinding() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			var login = post(client, "/login", session, credentials("alice", PASSWORD, csrf(get(client, "/api/csrf", session))));
			assertThat(login.statusCode()).isEqualTo(204);
			String replacement = cookie(login);
			assertRejected(confirm(client, replacement, enrollment), 400);
			assertRejected(cancel(client, replacement, enrollment.factorId()), 400);
			assertThat(factorState(userId)).isEqualTo("pending");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "1-1-1-1-1", "not-a-uuid", "00000000000000000000000000000001", "", "%2000000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000001%20" })
	void malformedOrShortenedFactorIdsCannotReachTheWorkflow(String factorId) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			begin(client, session, userId);
			String token = csrf(get(client, "/api/csrf", session));
			for (String suffix : List.of("/confirm", "/cancel")) {
				var response = post(client, PATH + suffix, session, "factorId=" + factorId + (suffix.equals("/confirm") ? "&code=123456" : "") + "&_csrf=" + encode(token));
				assertThat(response.statusCode()).isEqualTo(400);
			}
			assertThat(failures()).isZero();
			assertThat(factorState(userId)).isEqualTo("pending");
		}
	}

	@Test
	void aSecretProtectionFaultRejectsConfirmationButDoesNotPreventCancellation() throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var enrollment = begin(client, session, userId);
			this.jdbc.sql("UPDATE iam_user_totp SET key_id = repeat('0', 64)").update();
			assertUnavailable(confirm(client, session, enrollment));
			assertThat(failures()).isZero();
			assertThat(factorState(userId)).isEqualTo("pending");
			assertThat(codeCount()).isZero();
			assertThat(cancel(client, session, enrollment.factorId()).statusCode()).isEqualTo(204);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent", "deferred" })
	void aFailedRestartRestoresTheOldFactorSecretAndSessionBinding(String mode) throws Exception {
		UUID userId = activeUser("alice");
		try (var client = client()) {
			String session = login(client, "alice");
			var old = begin(client, session, userId);
			String body = enrollment(PASSWORD, csrf(get(client, "/api/csrf", session)));
			this.jdbc.sql("CREATE FUNCTION enrollment_restart_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.attribute_name = '" + IdentityBrowserSessions.TOTP_ENROLLMENT + "' THEN " + (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected restart failure';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER enrollment_restart_fault AFTER UPDATE ON iam_browser_session_attributes DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER enrollment_restart_fault BEFORE UPDATE ON iam_browser_session_attributes") + " FOR EACH ROW EXECUTE FUNCTION enrollment_restart_fault()").update();
			try { assertUnavailable(post(client, PATH, session, body)); }
			finally { this.jdbc.sql("DROP FUNCTION enrollment_restart_fault() CASCADE").update(); }
			assertThat(attribute(session, IdentityBrowserSessions.TOTP_ENROLLMENT)).isEqualTo(old.factorId());
			assertThat(events("totp_enrollment_started")).isEqualTo(1);
			assertThat(confirm(client, session, old).statusCode()).isEqualTo(200);
		}
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class ConcurrentRequests {
		@Bean RequestPause totpEnrollmentPause() { return new RequestPause(); }
		@Bean WebMvcConfigurer totpEnrollmentPauseConfiguration(RequestPause pause) {
			return new WebMvcConfigurer() {
				@Override public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(pause); }
			};
		}
	}

	static class RequestPause implements HandlerInterceptor {
		private volatile CountDownLatch entered;
		private volatile CountDownLatch release;
		private volatile boolean expirePassword;
		void start() { this.entered = new CountDownLatch(1); this.release = new CountDownLatch(1); this.expirePassword = false; }
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
	private String login(HttpClient client, String username) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(username, PASSWORD, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}
	private HttpResponse<String> start(HttpClient client, String session) throws Exception { return post(client, PATH, session, enrollment(PASSWORD, csrf(get(client, "/api/csrf", session)))); }
	private IdentityTotpEnrollment begin(HttpClient client, String session, UUID userId) throws Exception {
		var response = start(client, session);
		assertThat(response.statusCode()).isEqualTo(200);
		assertSecurityHeaders(response);
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		Map<String, Object> result = JsonPath.read(response.body(), "$");
		assertThat(result).containsOnlyKeys("factorId", "secret", "provisioningUri", "expiresAt");
		return new IdentityTotpEnrollment(userId, UUID.fromString(JsonPath.read(response.body(), "$.factorId")), JsonPath.read(response.body(), "$.secret"), JsonPath.read(response.body(), "$.provisioningUri"), Instant.parse(JsonPath.read(response.body(), "$.expiresAt")));
	}
	private HttpResponse<String> confirm(HttpClient client, String session, IdentityTotpEnrollment enrollment) throws Exception { return post(client, PATH + "/confirm", session, confirmation(enrollment, csrf(get(client, "/api/csrf", session)))); }
	private HttpResponse<String> cancel(HttpClient client, String session, UUID factorId) throws Exception { return post(client, PATH + "/cancel", session, cancellation(factorId, csrf(get(client, "/api/csrf", session)))); }
	private static String enrollment(String password, String csrf) { return (password == null ? "" : "currentPassword=" + encode(password) + "&") + "_csrf=" + encode(csrf); }
	private static String confirmation(IdentityTotpEnrollment enrollment, String csrf) { return "factorId=" + enrollment.factorId() + "&code=" + otp(enrollment) + "&_csrf=" + encode(csrf); }
	private static String cancellation(UUID factorId, String csrf) { return "factorId=" + factorId + "&_csrf=" + encode(csrf); }
	private String base() { return "https://localhost:" + this.port + PATH; }
	private String factorState(UUID userId) { return this.jdbc.sql("SELECT status FROM iam_user_totp WHERE user_id = :id").param("id", userId).query(String.class).single(); }
	private long codeCount() { return this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_code").query(Long.class).single(); }
	private long failures() { return this.jdbc.sql("SELECT COALESCE(sum(failures), 0) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single(); }
	private long passwordFailures(String dimension) { return this.jdbc.sql("SELECT COALESCE(sum(failures), 0) FROM iam_password_authentication_limit WHERE dimension = :dimension").param("dimension", dimension).query(Long.class).single(); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE source = :source AND action = :action").param("source", SOURCE).param("action", action).query(Long.class).single(); }
	private Object attribute(String cookie, String name) {
		return this.jdbc.sql("SELECT a.attribute_bytes FROM iam_browser_session_attributes a JOIN iam_browser_session s ON s.primary_id = a.session_primary_id WHERE s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).query(byte[].class).optional().map(SerializationUtils::deserialize).orElse(null);
	}
	private void setAttribute(String cookie, String name, Object value) {
		assertThat(this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update()).isEqualTo(1);
	}
	private void awaitBlocked(int pid) {
		await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))").param("pid", pid).query(Boolean.class).single());
	}
	private static void assertRejected(HttpResponse<String> response, int status) {
		assertThat(response.statusCode()).isEqualTo(status);
		assertSecurityHeaders(response);
		assertThat(response.body()).isEqualTo(status == 429 ? "Verification temporarily unavailable" : "TOTP enrollment rejected");
	}
	private static void assertUnavailable(HttpResponse<String> response) {
		assertThat(response.statusCode()).isEqualTo(503);
		assertSecurityHeaders(response);
		assertThat(response.body()).contains("SERVICE_UNAVAILABLE").doesNotContain("secret", "codes", "injected", "SQL", PASSWORD);
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
	}
	private static PasswordAuthenticationContext passwordContext() { return new PasswordAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-totp-enrollment-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String otp(IdentityTotpEnrollment enrollment) {
		long step = Math.floorDiv(Instant.now().getEpochSecond(), 30);
		byte[] counter = new byte[8]; for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(enrollment.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(java.util.Locale.ROOT, "%06d", number % 1_000_000);
	}

}
