package com.ixayda.iam.service;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityTotpsIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "Nine silver lanterns beyond the mountain";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:enrollment", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final List<String> OLD_TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit");

	@Autowired private IdentityTotps totps;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityPasswordRecoveries recoveries;
	@Autowired private IdentityPasswords changes;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	@MockitoSpyBean private TotpCodes codes;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("iam.totp.key-file", KEY_FILE::toString);
	}

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_user_totp", "iam_totp_authentication_limit", "iam_browser_session_attributes", "iam_browser_session",
				"iam_password_authentication_limit", "iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void independentReferenceCodesMatchRfc4226AndRfc6238Vectors() {
		byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
		String[] hotp = { "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489" };
		for (int step = 0; step < hotp.length; step++) { assertThat(referenceCode(secret, step)).isEqualTo(hotp[step]); }
		assertThat(referenceCode(secret, 1111111109L / 30)).isEqualTo("081804");
		assertThat(referenceCode(secret, 1111111111L / 30)).isEqualTo("050471");
		assertThat(referenceCode(secret, 1234567890L / 30)).isEqualTo("005924");
		assertThat(referenceCode(secret, 2000000000L / 30)).isEqualTo("279037");
		assertThat(referenceCode(secret, 20000000000L / 30)).isEqualTo("353130");
	}

	@Test
	void issuesOneTimeProvisioningMaterialAndStoresOnlyOwnerBoundCiphertext() throws Exception {
		var user = activeUser("alice");
		Instant before = Instant.now();
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(enrollment.userId()).isEqualTo(user.id());
		assertThat(enrollment.secret()).matches("[A-Z2-7]{32}");
		assertThat(enrollment.provisioningUri()).isEqualTo("otpauth://totp/IAM:" + user.id() + "?secret=" + enrollment.secret()
				+ "&issuer=IAM&algorithm=SHA1&digits=6&period=30");
		assertThat(enrollment.expiresAt()).isBetween(before.plusSeconds(600), Instant.now().plusSeconds(600));
		assertThat(enrollment.toString()).doesNotContain(enrollment.secret(), enrollment.provisioningUri());
		var stored = factor(user.id());
		assertThat(stored.get("factor_id")).isEqualTo(enrollment.factorId());
		assertThat(stored.get("status")).isEqualTo("pending");
		assertThat(stored.get("last_used_step")).isNull();
		assertThat(stored.get("secret_ciphertext").toString()).matches("v1\\.[A-Za-z0-9_-]{64}");
		assertThat(databaseText()).doesNotContain(enrollment.secret(), enrollment.provisioningUri(), PASSWORD);
		assertThat(this.totps.verify(user.id(), code(enrollment, step()), context())).isEmpty();
		assertThat(events("totp_enrollment_started")).hasSize(1).allSatisfy(event -> {
			assertThat(event.get("actor")).isEqualTo(SYSTEM.actor());
			assertThat(event.get("source")).isEqualTo(SYSTEM.source());
			assertThat(event.get("correlation_id")).isEqualTo(SYSTEM.correlationId());
		});
	}

	@Test
	void confirmsOnceAndConsumesTheConfirmingCodeBeforeAnyLaterVerification() throws Exception {
		var user = activeUser("alice");
		long step = step();
		var enrollment = distinctEnrollment(user.id(), step);
		String confirming = code(enrollment, step);
		var context = context();
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), confirming, context)).isTrue();
		assertThat(factor(user.id()).get("status")).isEqualTo("active");
		assertThat(factor(user.id()).get("last_used_step")).isEqualTo(step);
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), confirming, context)).isFalse();
		assertThat(this.totps.verify(user.id(), confirming, context)).isEmpty();
		var verified = this.totps.verify(user.id(), code(enrollment, step + 1), context).orElseThrow();
		assertThat(verified.step()).isEqualTo(step + 1);
		assertThat(verified.userId()).isEqualTo(user.id());
		assertThat(verified.factorId()).isEqualTo(enrollment.factorId());
		assertThat(verified.credentialVersion()).isEqualTo(1);
		assertThat(verified.correlationId()).isEqualTo(context.correlationId());
		assertThat(factor(user.id()).get("last_used_step")).isEqualTo(verified.step());
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
		assertThat(events("totp_enrollment_completed")).hasSize(1);
		assertThat(events("totp_authenticated")).hasSize(1).allSatisfy(event -> {
			assertThat(event.get("actor")).isEqualTo("user:" + user.id());
			assertThat(event.get("target_user_id")).isEqualTo(user.id());
		});
	}

	@Test
	void replacingAPendingEnrollmentInvalidatesOldConfirmationsAndCancellations() throws Exception {
		var user = activeUser("alice");
		var old = this.totps.beginEnrollment(user.id(), SYSTEM);
		var replacement = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(replacement.factorId()).isNotEqualTo(old.factorId());
		assertThat(replacement.secret()).isNotEqualTo(old.secret());
		assertThat(this.totps.confirmEnrollment(user.id(), old.factorId(), code(old, step()), context())).isFalse();
		assertThat(this.totps.cancelEnrollment(user.id(), old.factorId(), SYSTEM)).isFalse();
		assertThat(this.totps.confirmEnrollment(user.id(), replacement.factorId(), code(replacement, step()), context())).isTrue();
	}

	@Test
	void cancelsOnlyPendingEnrollmentAndCannotReplaceOrCancelAnActiveFactor() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(this.totps.cancelEnrollment(user.id(), enrollment.factorId(), SYSTEM)).isTrue();
		assertThat(this.totps.cancelEnrollment(user.id(), enrollment.factorId(), SYSTEM)).isFalse();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code(enrollment, step()), context())).isFalse();
		var active = activeFactor(user.id());
		var before = factor(user.id());
		assertThat(this.totps.cancelEnrollment(user.id(), active.factorId(), SYSTEM)).isFalse();
		assertThatIllegalStateException().isThrownBy(() -> this.totps.beginEnrollment(user.id(), SYSTEM));
		assertThat(factor(user.id())).isEqualTo(before);
		assertThat(events("totp_enrollment_cancelled")).hasSize(1);
	}

	@Test
	void rejectsExpiredRegistrationAndAllowsAReplacement() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		expire(user.id());
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code(enrollment, step()), context())).isFalse();
		assertThat(factor(user.id()).get("status")).isEqualTo("pending");
		var replacement = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(this.totps.confirmEnrollment(user.id(), replacement.factorId(), code(replacement, step()), context())).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "pending", "disabled", "missing-password" })
	void enrollmentRequiresAnActiveUserWithAPassword(String state) {
		var user = activeUser("alice");
		if (state.equals("missing-password")) {
			this.jdbc.sql("DELETE FROM iam_password WHERE user_id = :id").param("id", user.id()).update();
		}
		else { this.jdbc.sql("UPDATE iam_user SET status = :status WHERE id = :id").param("status", state).param("id", user.id()).update(); }
		assertThatIllegalStateException().isThrownBy(() -> this.totps.beginEnrollment(user.id(), SYSTEM));
		assertThat(events("totp_enrollment_started")).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "password-change", "password-recovery", "disable-enable" })
	void credentialVersionChangesInvalidatePendingEnrollment(String operation) throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		if (operation.equals("disable-enable")) {
			this.states.disable(user.id(), SYSTEM);
			this.states.enable(user.id(), SYSTEM);
		}
		else if (operation.equals("password-recovery")) {
			var proof = this.recoveries.issue(user.id(), SYSTEM);
			assertThat(this.recoveries.complete(user.id(), proof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID()))
					.isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
		}
		else {
			String sessionId = session(user.id());
			assertThat(this.changes.change(user.id(), sessionId, 1, System.currentTimeMillis(), PASSWORD, NEW_PASSWORD,
					new PasswordAuthenticationContext("browser:password-change", context().clientAddress(), UUID.randomUUID())))
					.isEqualTo(IdentityPasswords.Result.CHANGED);
		}
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code(enrollment, step()), context())).isFalse();
		assertThat(factor(user.id()).get("status")).isEqualTo("pending");
	}

	@Test
	void activeFactorSurvivesPasswordRecoveryButCannotAuthenticateADisabledUser() throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		this.recoveries.complete(user.id(), proof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID());
		this.states.disable(user.id(), SYSTEM);
		String code = code(enrollment, step());
		assertThat(this.totps.verify(user.id(), code, context())).isEmpty();
		this.states.enable(user.id(), SYSTEM);
		assertThat(this.totps.verify(user.id(), code, context()).orElseThrow().credentialVersion()).isEqualTo(3);
	}

	@Test
	void unknownAccountsWrongBindingsAndMissingFactorsAreOrdinaryAuditedFailures() throws Exception {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		var enrollment = this.totps.beginEnrollment(alice.id(), SYSTEM);
		String code = code(enrollment, step());
		assertThat(this.totps.confirmEnrollment(bob.id(), enrollment.factorId(), code, context())).isFalse();
		assertThat(this.totps.confirmEnrollment(alice.id(), UUID.randomUUID(), code, context())).isFalse();
		assertThat(this.totps.verify(bob.id(), code, context())).isEmpty();
		UUID unknown = UUID.randomUUID();
		assertThat(this.totps.verify(unknown, code, context())).isEmpty();
		assertThat(events("totp_auth_failed")).anySatisfy(event -> {
			assertThat(event.get("target_user_id")).isNull();
			assertThat(event.get("actor")).isEqualTo("anonymous");
		});
		assertThat(this.totps.confirmEnrollment(alice.id(), enrollment.factorId(), code, context())).isTrue();
	}

	@ParameterizedTest
	@MethodSource("invalidCodes")
	void malformedCodesCommitAFailureWithoutActivatingOrConsuming(String code) {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, context())).isFalse();
		assertThat(factor(user.id()).get("last_used_step")).isNull();
		assertThat(factor(user.id()).get("status")).isEqualTo("pending");
		assertThat(failures("account")).containsExactly(1);
		assertThat(failures("source")).containsExactly(1);
		assertThat(events("totp_enrollment_failed")).hasSize(1);
	}

	static Stream<String> invalidCodes() { return Stream.of(null, "", "12345", "1234567", "123456 ", "１２３４５６", "a\n"); }

	@Test
	void confirmationAndVerificationShareAccountBudgetAndReissuingDoesNotResetIt() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		for (int i = 0; i < 3; i++) { assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), "bad", context())).isFalse(); }
		for (int i = 0; i < 2; i++) { assertThat(this.totps.verify(user.id(), "bad", context())).isEmpty(); }
		var replacement = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(this.totps.confirmEnrollment(user.id(), replacement.factorId(), code(replacement, step()), context())).isFalse();
		assertThat(failures("account")).containsExactly(5);
		assertThat(events("totp_enrollment_throttled")).hasSize(1);
		this.jdbc.sql("UPDATE iam_totp_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
		assertThat(this.totps.confirmEnrollment(user.id(), replacement.factorId(), code(replacement, step()), context())).isTrue();
		assertThat(failures("account")).containsExactly(0);
	}

	@Test
	void sourceBudgetSpansAccountsAndEntryLabelsAndStopsCreatingNewAccountBuckets() {
		for (int i = 0; i < 30; i++) { assertThat(this.totps.verify(UUID.randomUUID(), "bad", context())).isEmpty(); }
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(30);
		var otherLabel = new TotpAuthenticationContext("another:entry", context().clientAddress(), UUID.randomUUID());
		assertThat(this.totps.verify(UUID.randomUUID(), "bad", otherLabel)).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(30);
		assertThat(failures("source")).containsExactly(30);
		assertThat(events("totp_auth_throttled")).hasSize(1);
	}

	@Test
	void accountBudgetSpansDifferentAddressesAndMappedIpv6SharesItsIpv4SourceBudget() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		for (int i = 1; i <= 5; i++) {
			var peer = new TotpAuthenticationContext("internal:test", InetAddress.getByName("192.0.2." + i), UUID.randomUUID());
			assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), "bad", peer)).isFalse();
		}
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code(enrollment, step()), context())).isFalse();
		assertThat(failures("account")).containsExactly(5);
		this.jdbc.sql("DELETE FROM iam_totp_authentication_limit").update();
		UUID unknown = UUID.randomUUID();
		assertThat(this.totps.verify(unknown, "bad", context())).isEmpty();
		byte[] mapped = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, 0, 2, 100 };
		var ipv6 = new TotpAuthenticationContext("other:entry", java.net.Inet6Address.getByAddress(null, mapped, -1), UUID.randomUUID());
		assertThat(this.totps.verify(unknown, "bad", ipv6)).isEmpty();
		assertThat(failures("source")).containsExactly(2);
	}

	@Test
	void successClearsOnlyTheAccountBudgetAndFailureBudgetsAreSeparateFromPasswordBudgets() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), "bad", context())).isFalse();
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code(enrollment, step()), context())).isTrue();
		assertThat(failures("account")).containsExactly(0);
		assertThat(failures("source")).containsExactly(1);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
	}

	@Test
	void futureStepConsumptionPreventsUsingAnEarlierCodeEvenWhenItIsStillInTheWindow() throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		long step = step();
		assertThat(this.totps.verify(user.id(), code(enrollment, step + 1), context())).isPresent();
		assertThat(this.totps.verify(user.id(), code(enrollment, step), context())).isEmpty();
		assertThat(this.totps.verify(user.id(), code(enrollment, step + 1), context())).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void concurrentRequestsCanConsumeTheCodeOnlyOnce(boolean confirmation) throws Exception {
		var user = activeUser("alice");
		var enrollment = confirmation ? this.totps.beginEnrollment(user.id(), SYSTEM) : activeFactor(user.id());
		String code = code(enrollment, step());
		var start = new CountDownLatch(1);
		var successes = new AtomicInteger();
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = Stream.of(1, 2).map(n -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				var peer = new TotpAuthenticationContext("internal:test", InetAddress.getByName("192.0.2." + n), UUID.randomUUID());
				boolean success = confirmation ? this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, peer)
						: this.totps.verify(user.id(), code, peer).isPresent();
				if (success) { successes.incrementAndGet(); }
				return success;
			})).toList();
			start.countDown();
			for (var task : tasks) { task.get(10, TimeUnit.SECONDS); }
		}
		assertThat(successes.get()).isEqualTo(1);
		assertThat(events(confirmation ? "totp_enrollment_completed" : "totp_authenticated")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "expiry", "disable", "version" })
	void waitingForAUserLockRechecksStateAfterTheLockIsAcquired(String change) throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		String code = code(enrollment, step());
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.lockById(user.id());
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				switch (change) {
					case "expiry" -> expire(user.id());
					case "disable" -> this.states.disable(user.id(), SYSTEM);
					case "version" -> this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id")
							.param("id", user.id()).update();
					default -> throw new AssertionError(change);
				}
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
				var attempt = executor.submit(() -> this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, context()));
				awaitUserLockWait();
				release.countDown();
				blocker.get(10, TimeUnit.SECONDS);
				assertThat(attempt.get(10, TimeUnit.SECONDS)).isFalse();
			}
			finally { release.countDown(); }
		}
		assertThat(factor(user.id()).get("status")).isEqualTo("pending");
	}

	@Test
	void expiryBetweenCodeCalculationAndConsumptionIsStillRejected() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		String code = code(enrollment, step());
		doAnswer(invocation -> {
			Object result = invocation.callRealMethod();
			expire(user.id());
			return result;
		}).when(this.codes).match(any(byte[].class), anyString(), any(Instant.class), anyLong());
		assertThat(this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, context())).isFalse();
		assertThat(factor(user.id()).get("status")).isEqualTo("pending");
		assertThat(factor(user.id()).get("last_used_step")).isNull();
		assertThat(events("totp_enrollment_completed")).isEmpty();
		assertThat(events("totp_enrollment_failed")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "totp_enrollment_started", "totp_enrollment_cancelled", "totp_enrollment_completed", "totp_authenticated", "totp_enrollment_failed", "totp_auth_failed" })
	void auditFailureRollsBackTheEntireDecisionAndItsFailureCounters(String action) throws Exception {
		var user = activeUser("alice");
		var enrollment = action.equals("totp_authenticated") || action.equals("totp_auth_failed") ? activeFactor(user.id())
				: this.totps.beginEnrollment(user.id(), SYSTEM);
		String code = code(enrollment, step());
		var before = allData();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT totp_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try {
			assertThatThrownBy(() -> {
				switch (action) {
					case "totp_enrollment_started" -> this.totps.beginEnrollment(user.id(), SYSTEM);
					case "totp_enrollment_cancelled" -> this.totps.cancelEnrollment(user.id(), enrollment.factorId(), SYSTEM);
					case "totp_enrollment_completed" -> this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, context());
					case "totp_authenticated" -> this.totps.verify(user.id(), code, context());
					case "totp_enrollment_failed" -> this.totps.confirmEnrollment(user.id(), enrollment.factorId(), "bad", context());
					case "totp_auth_failed" -> this.totps.verify(user.id(), "bad", context());
					default -> throw new AssertionError(action);
				}
			}).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT totp_test_reject").update(); }
		assertThat(allData()).isEqualTo(before);
	}

	@Test
	void corruptedCiphertextAndWrongKeyIdsAreInfrastructureFailuresNotSuccessfulOrOrdinaryDenials() throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		String code = code(enrollment, step());
		String original = factor(user.id()).get("secret_ciphertext").toString();
		String changed = original.substring(0, 3) + (original.charAt(3) == 'A' ? "B" : "A") + original.substring(4);
		this.jdbc.sql("UPDATE iam_user_totp SET secret_ciphertext = :value WHERE user_id = :id").param("value", changed).param("id", user.id()).update();
		var before = allData();
		assertThatIllegalStateException().isThrownBy(() -> this.totps.verify(user.id(), code, context()));
		assertThat(allData()).isEqualTo(before);
		this.jdbc.sql("UPDATE iam_user_totp SET secret_ciphertext = :secret, key_id = :key WHERE user_id = :id")
				.param("secret", original).param("key", "0".repeat(64)).param("id", user.id()).update();
		assertThatIllegalStateException().isThrownBy(() -> this.totps.verify(user.id(), code, context()));
	}

	@Test
	void silentlySuppressedConsumptionNeverPublishesASuccess() throws Exception {
		var user = activeUser("alice");
		var enrollment = this.totps.beginEnrollment(user.id(), SYSTEM);
		this.jdbc.sql("CREATE FUNCTION totp_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER totp_test_suppress BEFORE UPDATE ON iam_user_totp FOR EACH ROW EXECUTE FUNCTION totp_test_suppress()").update();
			String code = code(enrollment, step());
			assertThatIllegalStateException().isThrownBy(() -> this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, context()));
			assertThat(factor(user.id()).get("status")).isEqualTo("pending");
			assertThat(events("totp_enrollment_completed")).isEmpty();
		}
		finally { this.jdbc.sql("DROP FUNCTION totp_test_suppress() CASCADE").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "enroll", "confirm", "verify", "cancel" })
	void deferredCommitFailureRollsBackAndDoesNotReturnASecretOrSuccessfulDecision(String operation) throws Exception {
		var user = activeUser("alice");
		var enrollment = operation.equals("verify") ? activeFactor(user.id()) : this.totps.beginEnrollment(user.id(), SYSTEM);
		String code = code(enrollment, step());
		var before = allData();
		this.jdbc.sql("CREATE FUNCTION totp_test_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test commit failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE CONSTRAINT TRIGGER totp_test_commit_failure AFTER INSERT OR UPDATE OR DELETE ON iam_user_totp DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION totp_test_commit_failure()").update();
			assertThatThrownBy(() -> {
				switch (operation) {
					case "enroll" -> this.totps.beginEnrollment(user.id(), SYSTEM);
					case "confirm" -> this.totps.confirmEnrollment(user.id(), enrollment.factorId(), code, context());
					case "verify" -> this.totps.verify(user.id(), code, context());
					case "cancel" -> this.totps.cancelEnrollment(user.id(), enrollment.factorId(), SYSTEM);
					default -> throw new AssertionError(operation);
				}
			}).isInstanceOf(org.springframework.transaction.TransactionSystemException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION totp_test_commit_failure() CASCADE").update(); }
		assertThat(allData()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void failureToWriteTheBudgetNeverReturnsAnAuthenticationDecision(boolean valid) throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		String code = valid ? code(enrollment, step()) : "bad";
		var before = allData();
		this.jdbc.sql("CREATE FUNCTION totp_test_budget_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test budget failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER totp_test_budget_failure BEFORE UPDATE ON iam_totp_authentication_limit FOR EACH ROW EXECUTE FUNCTION totp_test_budget_failure()").update();
			assertThatThrownBy(() -> this.totps.verify(user.id(), code, context())).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION totp_test_budget_failure() CASCADE").update(); }
		assertThat(allData()).isEqualTo(before);
	}

	@Test
	void noConfiguredKeyLeavesExistingPasswordFeaturesAvailableButRefusesAllFactorDecisions() throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		String code = code(enrollment, step());
		var before = allData();
		try (var unconfigured = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword())).run("--iam.totp.key-file=")) {
			assertThat(unconfigured.getBean(IdentityUsers.class).findById(user.id())).contains(user);
			var service = unconfigured.getBean(IdentityTotps.class);
			assertThatIllegalStateException().isThrownBy(() -> service.beginEnrollment(user.id(), SYSTEM));
			assertThatIllegalStateException().isThrownBy(() -> service.verify(user.id(), code, context()));
		}
		assertThat(allData()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "status = 'unknown'", "last_used_step = 1", "secret_ciphertext = 'plaintext'", "key_id = 'unknown'",
			"enrollment_credential_version = 0", "expires_at = issued_at", "issued_at = '-infinity'" })
	void databaseRejectsInvalidFactorState(String assignment) {
		var user = activeUser("alice");
		this.totps.beginEnrollment(user.id(), SYSTEM);
		var before = factor(user.id());
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user_totp SET " + assignment + " WHERE user_id = :id")
				.param("id", user.id()).update()).isInstanceOf(DataAccessException.class);
		assertThat(factor(user.id())).isEqualTo(before);
	}

	@Test
	void rejectsAmbientTransactionsAndMissingInvocationContextBeforeAnyMutation() {
		var user = activeUser("alice");
		var before = allData();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> this.totps.beginEnrollment(user.id(), SYSTEM));
			assertThatIllegalStateException().isThrownBy(() -> this.totps.cancelEnrollment(user.id(), UUID.randomUUID(), SYSTEM));
			assertThatIllegalStateException().isThrownBy(() -> this.totps.confirmEnrollment(user.id(), UUID.randomUUID(), "bad", context()));
			assertThatIllegalStateException().isThrownBy(() -> this.totps.verify(user.id(), "bad", context()));
		});
		assertThatIllegalArgumentException().isThrownBy(() -> this.totps.beginEnrollment(null, SYSTEM));
		assertThatIllegalArgumentException().isThrownBy(() -> this.totps.beginEnrollment(user.id(), null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.totps.confirmEnrollment(user.id(), null, "bad", context()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.totps.verify(user.id(), "bad", null));
		assertThat(allData()).isEqualTo(before);
	}

	@Test
	void aNewApplicationContextUsesThePersistedSecretAndCannotReplayAPreviousDecision() throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		String code = code(enrollment, step());
		assertThat(this.totps.verify(user.id(), code, context())).isPresent();
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword(), "iam.totp.key-file", KEY_FILE.toString())).run()) {
			var service = restarted.getBean(IdentityTotps.class);
			assertThat(service.verify(user.id(), code, context())).isEmpty();
			assertThat(service.verify(user.id(), code(enrollment, step() + 1), context())).isPresent();
		}
	}

	@Test
	void aNewApplicationContextRetainsTheFailureBudgetUntilItsDatabaseWindowExpires() throws Exception {
		var user = activeUser("alice");
		var enrollment = activeFactor(user.id());
		for (int i = 0; i < 5; i++) { assertThat(this.totps.verify(user.id(), "bad", context())).isEmpty(); }
		String code = code(enrollment, step());
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword(), "iam.totp.key-file", KEY_FILE.toString())).run()) {
			var service = restarted.getBean(IdentityTotps.class);
			assertThat(service.verify(user.id(), code, context())).isEmpty();
			assertThat(events("totp_auth_throttled")).hasSize(1);
			this.jdbc.sql("UPDATE iam_totp_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
			assertThat(service.verify(user.id(), code, context())).isPresent();
		}
	}

	@Test
	void boundedCleanupRemovesOnlyStaleBudgetsWithoutErasingReplayStateOrFactors() throws Exception {
		var user = activeUser("alice");
		activeFactor(user.id());
		this.totps.verify(user.id(), "bad", context());
		this.jdbc.sql("UPDATE iam_totp_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '2 days' WHERE dimension = 'source'").update();
		var before = factor(user.id());
		this.totps.cleanUpExpiredLimits();
		assertThat(failures("source")).isEmpty();
		assertThat(failures("account")).containsExactly(1);
		assertThat(factor(user.id())).isEqualTo(before);
	}

	@Test
	void upgradesV11WithoutAddingFactorsOrChangingExistingBusinessData() throws Exception {
		var user = activeUser("alice");
		String schema = "totp_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "11").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : OLD_TABLES) { copyRows(previous, table); }
				var before = snapshot(previous, OLD_TABLES);
				flyway(schema, "12").migrate();
				assertThat(snapshot(previous, OLD_TABLES)).isEqualTo(before);
				assertThat(previous.sql("SELECT count(*) FROM iam_user_totp").query(Long.class).single()).isZero();
				assertThat(previous.sql("SELECT count(*) FROM iam_totp_authentication_limit").query(Long.class).single()).isZero();
				assertThat(previous.sql("SELECT status FROM iam_user WHERE id = :id").param("id", user.id()).query(String.class).single()).isEqualTo("active");
				assertThat(flyway(schema, "12").migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private IdentityUser activeUser(String username) {
		var user = this.users.create(username, "Private Name", SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(user.id()).orElseThrow();
	}

	private String session(UUID userId) {
		String id = UUID.randomUUID().toString();
		long now = System.currentTimeMillis();
		this.jdbc.sql("""
				INSERT INTO iam_browser_session (primary_id, session_id, creation_time, last_access_time,
				max_inactive_interval, expiry_time, principal_name) VALUES (:id, :id, :now, :now, 1800, :expiry, :principal)
				""").param("id", id).param("now", now).param("expiry", now + 1800000).param("principal", userId.toString()).update();
		return id;
	}

	private IdentityTotpEnrollment distinctEnrollment(UUID userId, long step) {
		for (int i = 0; i < 10; i++) {
			var enrollment = this.totps.beginEnrollment(userId, SYSTEM);
			if (Stream.of(code(enrollment, step - 1), code(enrollment, step), code(enrollment, step + 1)).distinct().count() == 3) { return enrollment; }
		}
		throw new AssertionError("Cannot build a fixture with distinct adjacent codes");
	}

	private IdentityTotpEnrollment activeFactor(UUID userId) {
		long step = step();
		var enrollment = distinctEnrollment(userId, step);
		// Seed prior consumption for verification tests; enrollment confirmation is tested through the service separately.
		assertThat(this.jdbc.sql("""
				UPDATE iam_user_totp SET status = 'active', activated_at = issued_at, last_used_step = :step
				WHERE user_id = :id AND factor_id = :factorId AND status = 'pending'
				""").param("step", step - 1).param("id", userId).param("factorId", enrollment.factorId()).update()).isEqualTo(1);
		return enrollment;
	}

	private long step() {
		return this.jdbc.sql("SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::BIGINT").query(Long.class).single();
	}

	private static String code(IdentityTotpEnrollment enrollment, long step) {
		return referenceCode(Base32.decode(enrollment.secret()), step);
	}

	private static String referenceCode(byte[] secret, long step) {
		// Independent test oracle: Bouncy Castle HMAC, explicit byte encoding and truncation.
		byte[] counter = new byte[8];
		for (int index = counter.length - 1; index >= 0; index--) {
			counter[index] = (byte) step;
			step >>>= 8;
		}
		HMac mac = new HMac(new SHA1Digest());
		mac.init(new KeyParameter(secret));
		mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()];
		mac.doFinal(hash, 0);
		int offset = hash[19] & 15;
		int binary = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16)
				| ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(Locale.ROOT, "%06d", binary % 1_000_000);
	}

	private static TotpAuthenticationContext context() {
		try { return new TotpAuthenticationContext("internal:totp", InetAddress.getByName("192.0.2.100"), UUID.randomUUID()); }
		catch (Exception ex) { throw new IllegalStateException(ex); }
	}

	private static Path keyFile() {
		try {
			byte[] key = new byte[32];
			new SecureRandom().nextBytes(key);
			Path path = Files.createTempFile("iam-totp-test-", ".key");
			Files.write(path, key);
			path.toFile().deleteOnExit();
			return path;
		}
		catch (Exception ex) { throw new IllegalStateException(ex); }
	}

	private Map<String, Object> factor(UUID userId) {
		return this.jdbc.sql("SELECT * FROM iam_user_totp WHERE user_id = :id").param("id", userId).query().singleRow();
	}

	private List<Map<String, Object>> events(String action) {
		return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = :action").param("action", action).query().listOfRows();
	}

	private List<Integer> failures(String dimension) {
		return this.jdbc.sql("SELECT failures FROM iam_totp_authentication_limit WHERE dimension = :dimension ORDER BY subject_key")
				.param("dimension", dimension).query(Integer.class).list();
	}

	private void expire(UUID userId) {
		this.jdbc.sql("UPDATE iam_user_totp SET issued_at = clock_timestamp() - INTERVAL '11 minutes', expires_at = clock_timestamp() - INTERVAL '1 second' WHERE user_id = :id")
				.param("id", userId).update();
	}

	private void awaitUserLockWait() throws Exception {
		long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		while (System.nanoTime() < until) {
			if (this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%iam_user%FOR UPDATE%'")
					.query(Long.class).single() > 0) { return; }
			Thread.sleep(10);
		}
		throw new AssertionError("Verification did not reach the user lock");
	}

	private List<List<String>> allData() {
		var tables = new java.util.ArrayList<>(OLD_TABLES);
		tables.addAll(List.of("iam_user_totp", "iam_totp_authentication_limit"));
		return snapshot(this.jdbc, tables);
	}

	private String databaseText() { return allData().toString(); }

	private List<List<String>> snapshot(JdbcClient client, List<String> tables) {
		return tables.stream().map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
