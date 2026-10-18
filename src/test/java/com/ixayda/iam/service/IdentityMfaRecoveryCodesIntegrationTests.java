package com.ixayda.iam.service;

import java.net.Inet6Address;
import java.net.InetAddress;
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
import java.util.stream.Stream;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.MfaRecoveryCodes;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityMfaRecoveryCodesIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "Nine silver lanterns beyond the mountain";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:setup", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final List<String> OLD_TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit",
			"iam_user_totp", "iam_totp_authentication_limit");
	private static final List<String> TABLES = Stream.concat(OLD_TABLES.stream(),
			Stream.of("iam_mfa_recovery_code", "iam_mfa_recovery_limit")).toList();

	@Autowired private IdentityMfaRecoveryCodes recovery;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityPasswordRecoveries passwordRecoveries;
	@Autowired private MfaRecoveryCodes codes;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("iam.totp.key-file", KEY_FILE::toString);
	}

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_mfa_recovery_code", "iam_mfa_recovery_limit", "iam_user_totp", "iam_totp_authentication_limit",
				"iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit", "iam_security_audit",
				"iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void generatesTenOnceDeliveredCodesWithOnlyOwnerBoundDigestsPersisted() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var context = totpContext();
		Instant before = Instant.now();
		String totp = freshTotp(factor);
		var result = this.recovery.issue(user.id(), totp, context).orElseThrow();
		assertThat(result.userId()).isEqualTo(user.id());
		assertThat(result.factorId()).isEqualTo(factor.factorId());
		assertThat(result.issuedAt()).isBetween(before, Instant.now());
		assertThat(result.codes()).hasSize(10).doesNotHaveDuplicates().allMatch(code -> code.matches("[0-9a-f]{4}(?:-[0-9a-f]{4}){7}"));
		assertThatThrownBy(() -> result.codes().clear()).isInstanceOf(UnsupportedOperationException.class);
		assertThat(result.toString()).doesNotContain(result.codes().toArray(String[]::new));
		assertThat(snapshot(this.jdbc, TABLES).toString()).doesNotContain(result.codes().toArray(String[]::new)).doesNotContain(PASSWORD, factor.secret());
		assertThat(codeRows()).hasSize(10).allSatisfy(row -> {
			assertThat(row.get("user_id")).isEqualTo(user.id());
			assertThat(row.get("factor_id")).isEqualTo(factor.factorId());
			assertThat(row.get("generation_id")).isEqualTo(result.generationId());
			assertThat(row.get("consumed_at")).isNull();
		});
		assertThat(this.totps.verify(user.id(), totp, context)).isEmpty();
		assertThat(events("mfa_recovery_codes_generated")).hasSize(1).allSatisfy(row -> {
			assertThat(row.get("actor")).isEqualTo("user:" + user.id());
			assertThat(row.get("source")).isEqualTo(context.source());
			assertThat(row.get("correlation_id")).isEqualTo(context.correlationId());
		});
		assertThat(events("totp_authenticated")).hasSize(1);
	}

	@Test
	void consumesEachCodeOnceWithoutAuthenticatingOrReplacingTheFactor() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		var before = factorRow(user.id());
		for (String code : set.codes()) {
			var context = recoveryContext();
			var result = this.recovery.consume(user.id(), code, context).orElseThrow();
			assertThat(result.userId()).isEqualTo(user.id());
			assertThat(result.factorId()).isEqualTo(factor.factorId());
			assertThat(result.generationId()).isEqualTo(set.generationId());
			assertThat(result.credentialVersion()).isEqualTo(1);
			assertThat(result.consumedAt()).isBetween(set.issuedAt(), Instant.now());
			assertThat(result.correlationId()).isEqualTo(context.correlationId());
			assertThat(this.recovery.consume(user.id(), code, context)).isEmpty();
		}
		assertThat(codeRows()).hasSize(10).allSatisfy(row -> assertThat(row.get("consumed_at")).isNotNull());
		assertThat(factorRow(user.id())).isEqualTo(before);
		assertThat(events("mfa_recovery_code_consumed")).hasSize(10);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
	}

	@Test
	void regenerationInvalidatesUnusedAndConsumedOldCodesOnlyAfterFreshTotpVerification() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var first = issue(factor);
		assertThat(this.recovery.consume(user.id(), first.codes().getFirst(), recoveryContext())).isPresent();
		var before = codeRows();
		assertThat(this.recovery.issue(user.id(), "bad", totpContext())).isEmpty();
		assertThat(codeRows()).isEqualTo(before);
		var second = issue(factor);
		assertThat(second.generationId()).isNotEqualTo(first.generationId());
		assertThat(second.codes()).doesNotContainAnyElementsOf(first.codes());
		assertThat(this.recovery.consume(user.id(), first.codes().get(1), recoveryContext())).isEmpty();
		assertThat(this.recovery.consume(user.id(), second.codes().getFirst(), recoveryContext())).isPresent();
		assertThat(events("mfa_recovery_codes_generated")).hasSize(2);
		assertThat(codeRows()).hasSize(10).allSatisfy(row -> assertThat(row.get("generation_id")).isEqualTo(second.generationId()));
	}

	@ParameterizedTest
	@ValueSource(strings = { "unknown", "pending", "no-password", "no-factor", "pending-factor", "disabled" })
	void generationRequiresAnActiveUserPasswordAndVerifiedActiveFactor(String state) {
		UUID id = UUID.randomUUID();
		String code = "123456";
		if (!state.equals("unknown")) {
			var user = state.equals("pending") || state.equals("no-password") ? this.users.create("alice", "Alice", SYSTEM) : activeUser("alice");
			id = user.id();
			if (state.equals("pending")) { this.users.setInitialPassword(id, PASSWORD, SYSTEM); }
			if (state.equals("pending-factor")) { this.totps.beginEnrollment(id, SYSTEM); }
			if (state.equals("disabled")) {
				var factor = activeFactor(id);
				code = freshTotp(factor);
				this.states.disable(id, SYSTEM);
			}
		}
		assertThat(this.recovery.issue(id, code, totpContext())).isEmpty();
		assertThat(codeRows()).isEmpty();
		assertThat(events("mfa_recovery_codes_generated")).isEmpty();
		assertThat(events("totp_auth_failed")).hasSize(1);
	}

	@ParameterizedTest
	@MethodSource("invalidCodes")
	void malformedCodesPersistFailureAndBudgetsWithoutConsumingAnything(String code) {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var before = codeRows();
		assertThat(this.recovery.consume(user.id(), code, recoveryContext())).isEmpty();
		assertThat(codeRows()).isEqualTo(before);
		assertThat(failures("account")).containsExactly(1);
		assertThat(failures("source")).containsExactly(1);
		assertThat(events("mfa_recovery_code_failed")).hasSize(1).allSatisfy(row -> {
			assertThat(row.get("actor")).isEqualTo("anonymous");
			assertThat(row.get("target_user_id")).isEqualTo(set.userId());
		});
	}

	static Stream<String> invalidCodes() {
		return Stream.of(null, "", "123456", "0123456789abcdef0123456789abcdef", "0123-4567-89AB-CDEF-0123-4567-89AB-CDEF",
				"0123-4567-89ab-cdef-0123-4567-89ab-cdef\n", "x".repeat(65536));
	}

	@Test
	void rejectsCrossUserCodesUnknownUsersAndDisabledAccountsWithoutConsumingTheCode() {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		var set = issue(activeFactor(alice.id()));
		activeFactor(bob.id());
		var before = codeRows();
		assertThat(this.recovery.consume(bob.id(), set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(this.recovery.consume(UUID.randomUUID(), set.codes().getFirst(), recoveryContext())).isEmpty();
		this.states.disable(alice.id(), SYSTEM);
		assertThat(this.recovery.consume(alice.id(), set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(codeRows()).isEqualTo(before);
		assertThat(events("mfa_recovery_code_failed")).hasSize(3).anySatisfy(row -> assertThat(row.get("target_user_id")).isNull());
		this.states.enable(alice.id(), SYSTEM);
		assertThat(this.recovery.consume(alice.id(), set.codes().getFirst(), recoveryContext())).isPresent();
	}

	@Test
	void ordinaryPasswordRecoveryPreservesFactorAndSingleUseState() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		assertThat(this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext())).isPresent();
		var proof = this.passwordRecoveries.issue(user.id(), SYSTEM);
		this.passwordRecoveries.complete(user.id(), proof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID());
		assertThat(this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(this.recovery.consume(user.id(), set.codes().get(1), recoveryContext())).get()
				.satisfies(value -> assertThat(value.credentialVersion()).isEqualTo(2));
	}

	@Test
	void concurrentConsumptionFromDifferentPeersSucceedsExactlyOnce() throws Exception {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = Stream.of(1, 2).map(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				return this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext("192.0.2." + index)).isPresent();
			})).toList();
			start.countDown();
			int successes = 0;
			for (var task : tasks) { if (task.get(10, TimeUnit.SECONDS)) { successes++; } }
			assertThat(successes).isEqualTo(1);
		}
		assertThat(events("mfa_recovery_code_consumed")).hasSize(1);
		assertThat(codeRows().stream().filter(row -> row.get("consumed_at") != null)).hasSize(1);
	}

	@Test
	void concurrentGenerationWithTheSameTotpPublishesOnlyOneSet() throws Exception {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		String code = freshTotp(factor);
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = Stream.of(1, 2).map(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				return this.recovery.issue(user.id(), code, totpContext()).isPresent();
			})).toList();
			start.countDown();
			int successes = 0;
			for (var task : tasks) { if (task.get(10, TimeUnit.SECONDS)) { successes++; } }
			assertThat(successes).isEqualTo(1);
		}
		assertThat(codeRows()).hasSize(10);
		assertThat(events("mfa_recovery_codes_generated")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "disable", "no-password", "delete-factor", "remove-code-set" })
	void waitingForTheUserLockRechecksCurrentStateAndCurrentCodeSet(String change) throws Exception {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.lockById(user.id());
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				switch (change) {
					case "disable" -> this.states.disable(user.id(), SYSTEM);
					case "no-password" -> this.jdbc.sql("DELETE FROM iam_password WHERE user_id = :id").param("id", user.id()).update();
					case "delete-factor" -> this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :id").param("id", user.id()).update();
					case "remove-code-set" -> this.jdbc.sql("DELETE FROM iam_mfa_recovery_code WHERE user_id = :id").param("id", user.id()).update();
					default -> throw new AssertionError(change);
				}
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
				var attempt = executor.submit(() -> this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext()));
				awaitUserLockWait();
				release.countDown();
				blocker.get(10, TimeUnit.SECONDS);
				assertThat(attempt.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
		assertThat(events("mfa_recovery_code_consumed")).isEmpty();
		assertThat(events("mfa_recovery_code_failed")).hasSize(1);
	}

	@Test
	void accountBudgetSpansPeersAndDoesNotConsumeTheCorrectCodeWhileBlocked() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		for (int index = 1; index <= 5; index++) {
			assertThat(this.recovery.consume(user.id(), "bad", recoveryContext("192.0.2." + index))).isEmpty();
		}
		assertThat(this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(failures("account")).containsExactly(5);
		assertThat(codeRows()).allSatisfy(row -> assertThat(row.get("consumed_at")).isNull());
		assertThat(events("mfa_recovery_code_throttled")).hasSize(1);
		this.jdbc.sql("UPDATE iam_mfa_recovery_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
		assertThat(this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext())).isPresent();
	}

	@Test
	void sourceBudgetSpansAccountsAndEntryNamesAndPreventsNewAccountBuckets() {
		for (int index = 0; index < 30; index++) {
			assertThat(this.recovery.consume(UUID.randomUUID(), "bad", recoveryContext())).isEmpty();
		}
		var otherEntry = new MfaRecoveryCodeContext("another:entry", recoveryContext().clientAddress(), UUID.randomUUID());
		assertThat(this.recovery.consume(UUID.randomUUID(), "bad", otherEntry)).isEmpty();
		assertThat(failures("source")).containsExactly(30);
		assertThat(failures("account")).hasSize(30);
		assertThat(events("mfa_recovery_code_throttled")).hasSize(1);
	}

	@Test
	void ipv4AndMappedIpv6ShareTheSameSourceBudget() throws Exception {
		UUID unknown = UUID.randomUUID();
		assertThat(this.recovery.consume(unknown, "bad", recoveryContext())).isEmpty();
		byte[] mapped = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, 0, 2, 100 };
		var context = new MfaRecoveryCodeContext("other:entry", Inet6Address.getByAddress(null, mapped, -1), UUID.randomUUID());
		assertThat(this.recovery.consume(unknown, "bad", context)).isEmpty();
		assertThat(failures("source")).containsExactly(2);
	}

	@Test
	void successResetsOnlyItsRecoveryAccountBudgetAndGenerationDoesNotResetRecoveryLimits() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var first = issue(factor);
		assertThat(this.recovery.consume(user.id(), "bad", recoveryContext())).isEmpty();
		assertThat(this.recovery.consume(user.id(), first.codes().getFirst(), recoveryContext())).isPresent();
		assertThat(failures("account")).containsExactly(0);
		assertThat(failures("source")).containsExactly(1);
		assertThat(this.recovery.consume(user.id(), "bad", recoveryContext())).isEmpty();
		issue(factor);
		assertThat(failures("account")).containsExactly(1);
		assertThat(failures("source")).containsExactly(2);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "mfa_recovery_codes_generated", "totp_authenticated", "mfa_recovery_code_consumed", "mfa_recovery_code_failed", "mfa_recovery_code_throttled" })
	void auditFailuresRollBackCodesFactorConsumptionAndBudgets(String action) {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		String code = freshTotp(factor);
		if (action.equals("mfa_recovery_code_throttled")) {
			for (int index = 0; index < 5; index++) { this.recovery.consume(user.id(), "bad", recoveryContext()); }
		}
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT recovery_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try {
			assertThatThrownBy(() -> {
				if (action.equals("mfa_recovery_codes_generated") || action.equals("totp_authenticated")) {
					this.recovery.issue(user.id(), code, totpContext());
				}
				else { this.recovery.consume(user.id(), action.equals("mfa_recovery_code_failed") ? "bad" : set.codes().getFirst(), recoveryContext()); }
			}).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT recovery_test_reject").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "consume" })
	void deferredCommitFailureNeverReturnsSecretsOrASuccessfulConsumption(String operation) {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		String code = freshTotp(factor);
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION recovery_test_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test commit failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE CONSTRAINT TRIGGER recovery_test_commit_failure AFTER INSERT OR UPDATE OR DELETE ON iam_mfa_recovery_code DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION recovery_test_commit_failure()").update();
			assertThatThrownBy(() -> {
				if (operation.equals("issue")) { this.recovery.issue(user.id(), code, totpContext()); }
				else { this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext()); }
			}).isInstanceOf(TransactionSystemException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION recovery_test_commit_failure() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void requiredBudgetWriteFailureNeverReturnsADecision(boolean valid) {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION recovery_test_budget_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test budget failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER recovery_test_budget_failure BEFORE UPDATE ON iam_mfa_recovery_limit FOR EACH ROW EXECUTE FUNCTION recovery_test_budget_failure()").update();
			assertThatThrownBy(() -> this.recovery.consume(user.id(), valid ? set.codes().getFirst() : "bad", recoveryContext())).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION recovery_test_budget_failure() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void silentlySuppressedCodeReplacementRollsBackTotpAndRetainsThePreviousSet() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		issue(factor);
		String code = freshTotp(factor);
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION recovery_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER recovery_test_suppress BEFORE DELETE ON iam_mfa_recovery_code FOR EACH ROW EXECUTE FUNCTION recovery_test_suppress()").update();
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.issue(user.id(), code, totpContext()));
		}
		finally { this.jdbc.sql("DROP FUNCTION recovery_test_suppress() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void silentlySuppressedConsumptionNeverPublishesASuccess() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION recovery_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER recovery_test_suppress BEFORE UPDATE ON iam_mfa_recovery_code FOR EACH ROW EXECUTE FUNCTION recovery_test_suppress()").update();
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext()));
		}
		finally { this.jdbc.sql("DROP FUNCTION recovery_test_suppress() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void silentlySuppressedFailureCounterDoesNotReturnAnUnmeteredDenial() {
		var user = activeUser("alice");
		issue(activeFactor(user.id()));
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION recovery_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER recovery_test_suppress BEFORE UPDATE ON iam_mfa_recovery_limit FOR EACH ROW EXECUTE FUNCTION recovery_test_suppress()").update();
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.consume(user.id(), "bad", recoveryContext()));
		}
		finally { this.jdbc.sql("DROP FUNCTION recovery_test_suppress() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void rejectsAmbientTransactionsAndMissingContextBeforeMutation() {
		var user = activeUser("alice");
		var before = snapshot(this.jdbc, TABLES);
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.issue(user.id(), "123456", totpContext()));
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.consume(user.id(), "bad", recoveryContext()));
		});
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.issue(null, "123456", totpContext()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.issue(user.id(), "123456", null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.consume(null, "bad", recoveryContext()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.consume(user.id(), "bad", null));
		assertThatThrownBy(() -> this.totps.verifyInTransaction(user.id(), "123456", totpContext()))
				.isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void restartKeepsReplayAndThrottleStateAndConsumptionDoesNotRequireDecryptingTotp() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		assertThat(this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext())).isPresent();
		for (int index = 0; index < 5; index++) { this.recovery.consume(user.id(), "bad", recoveryContext()); }
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword())).run("--iam.totp.key-file=")) {
			var service = restarted.getBean(IdentityMfaRecoveryCodes.class);
			assertThat(service.consume(user.id(), set.codes().get(1), recoveryContext())).isEmpty();
			this.jdbc.sql("UPDATE iam_mfa_recovery_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
			assertThat(service.consume(user.id(), set.codes().getFirst(), recoveryContext())).isEmpty();
			assertThat(service.consume(user.id(), set.codes().get(1), recoveryContext())).isPresent();
			var before = snapshot(this.jdbc, TABLES);
			assertThatIllegalStateException().isThrownBy(() -> service.issue(user.id(), "123456", totpContext()));
			assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
		}
	}

	@Test
	void cleanupDeletesOnlyStaleBudgetsAndPreservesCodesIncludingTheirReplayState() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		this.recovery.consume(user.id(), set.codes().getFirst(), recoveryContext());
		this.recovery.consume(user.id(), "bad", recoveryContext());
		this.jdbc.sql("UPDATE iam_mfa_recovery_limit SET window_started_at = clock_timestamp() - INTERVAL '2 days' WHERE dimension = 'source'").update();
		var before = codeRows();
		this.recovery.cleanUpExpiredLimits();
		assertThat(failures("source")).isEmpty();
		assertThat(failures("account")).containsExactly(1);
		assertThat(codeRows()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "code_digest = 'plaintext'", "issued_at = '-infinity'", "consumed_at = issued_at - INTERVAL '1 second'", "consumed_at = 'infinity'", "factor_id = gen_random_uuid()" })
	void databaseRejectsInvalidDigestsTimesAndFactorBindings(String assignment) {
		var user = activeUser("alice");
		issue(activeFactor(user.id()));
		var before = codeRows();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_mfa_recovery_code SET " + assignment).update()).isInstanceOf(DataAccessException.class);
		assertThat(codeRows()).isEqualTo(before);
	}

	@Test
	void databaseRejectsAnotherUsersFactorAndDeletingAFactorInvalidatesAllItsCodes() {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		var set = issue(activeFactor(alice.id()));
		var bobsFactor = activeFactor(bob.id());
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_mfa_recovery_code SET factor_id = :id")
				.param("id", bobsFactor.factorId()).update()).isInstanceOf(DataAccessException.class);
		this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :id").param("id", alice.id()).update();
		assertThat(codeRows()).isEmpty();
		activeFactor(alice.id());
		assertThat(this.recovery.consume(alice.id(), set.codes().getFirst(), recoveryContext())).isEmpty();
	}

	@Test
	void upgradesV12WithoutChangingExistingDataAndDoesNotInventRecoveryCodes() throws Exception {
		var user = activeUser("alice");
		activeFactor(user.id());
		String schema = "recovery_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "12").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : OLD_TABLES) { previous.sql("INSERT INTO " + table + " SELECT * FROM public." + table).update(); }
				var before = snapshot(previous, OLD_TABLES);
				flyway(schema, "13").migrate();
				assertThat(snapshot(previous, OLD_TABLES)).isEqualTo(before);
				assertThat(previous.sql("SELECT count(*) FROM iam_mfa_recovery_code").query(Long.class).single()).isZero();
				assertThat(previous.sql("SELECT count(*) FROM iam_mfa_recovery_limit").query(Long.class).single()).isZero();
				assertThat(flyway(schema, "13").migrate().migrationsExecuted).isZero();
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

	private IdentityTotpEnrollment activeFactor(UUID userId) {
		for (int attempt = 0; attempt < 10; attempt++) {
			var enrollment = this.totps.beginEnrollment(userId, SYSTEM);
			long step = step();
			if (Stream.of(step - 1, step, step + 1, step + 2).map(value -> referenceTotp(enrollment, value)).distinct().count() == 4) {
				// Activation fixtures keep these tests focused on code workflows; confirmation has its own integration coverage.
				this.jdbc.sql("UPDATE iam_user_totp SET status = 'active', activated_at = issued_at, last_used_step = :step WHERE user_id = :id")
						.param("step", step - 1).param("id", userId).update();
				return enrollment;
			}
		}
		throw new AssertionError("Cannot create distinct adjacent TOTP codes for the fixture");
	}

	private String freshTotp(IdentityTotpEnrollment factor) {
		long last = ((Number) factorRow(factor.userId()).get("last_used_step")).longValue();
		long step = Math.max(step(), last + 1);
		return referenceTotp(factor, step);
	}

	private static String referenceTotp(IdentityTotpEnrollment factor, long step) {
		byte[] counter = new byte[8];
		for (int index = 7; index >= 0; index--) { counter[index] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest());
		mac.init(new KeyParameter(Base32.decode(factor.secret())));
		mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()];
		mac.doFinal(hash, 0);
		int offset = hash[19] & 15;
		int binary = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16)
				| ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(Locale.ROOT, "%06d", binary % 1_000_000);
	}

	private MfaRecoveryCodeSet issue(IdentityTotpEnrollment factor) {
		return this.recovery.issue(factor.userId(), freshTotp(factor), totpContext()).orElseThrow();
	}

	private long step() {
		return this.jdbc.sql("SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::BIGINT").query(Long.class).single();
	}

	private Map<String, Object> factorRow(UUID userId) {
		return this.jdbc.sql("SELECT * FROM iam_user_totp WHERE user_id = :id").param("id", userId).query().singleRow();
	}

	private List<Map<String, Object>> codeRows() {
		return this.jdbc.sql("SELECT * FROM iam_mfa_recovery_code ORDER BY user_id, code_digest").query().listOfRows();
	}

	private List<Map<String, Object>> events(String action) {
		return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = :action").param("action", action).query().listOfRows();
	}

	private List<Integer> failures(String dimension) {
		return this.jdbc.sql("SELECT failures FROM iam_mfa_recovery_limit WHERE dimension = :dimension ORDER BY subject_key")
				.param("dimension", dimension).query(Integer.class).list();
	}

	private static TotpAuthenticationContext totpContext() {
		var recovery = recoveryContext();
		return new TotpAuthenticationContext("internal:mfa-codes", recovery.clientAddress(), UUID.randomUUID());
	}

	private static MfaRecoveryCodeContext recoveryContext() { return recoveryContext("192.0.2.100"); }

	private static MfaRecoveryCodeContext recoveryContext(String address) {
		try { return new MfaRecoveryCodeContext("internal:mfa-recovery", InetAddress.getByName(address), UUID.randomUUID()); }
		catch (Exception ex) { throw new IllegalStateException(ex); }
	}

	private static Path keyFile() {
		try {
			byte[] key = new byte[32];
			new SecureRandom().nextBytes(key);
			Path file = Files.createTempFile("iam-mfa-recovery-test-", ".key");
			Files.write(file, key);
			file.toFile().deleteOnExit();
			return file;
		}
		catch (Exception ex) { throw new IllegalStateException(ex); }
	}

	private List<List<String>> snapshot(JdbcClient client, List<String> tables) {
		return tables.stream().map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
	}

	private void awaitUserLockWait() throws Exception {
		long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		while (System.nanoTime() < until) {
			if (this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%iam_user%FOR UPDATE%'")
					.query(Long.class).single() > 0) { return; }
			Thread.sleep(10);
		}
		throw new AssertionError("Recovery consumption did not reach the user lock");
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
