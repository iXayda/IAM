package com.ixayda.iam.service;

import java.net.InetAddress;
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
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
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
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAdministratorsIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:setup", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final List<String> TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit",
			"iam_user_totp", "iam_totp_authentication_limit", "iam_mfa_recovery_code", "iam_mfa_recovery_limit", "iam_totp_recovery",
			"iam_totp_replacement", "iam_administrator", "iam_admin_bootstrap");

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private IdentityTotpReplacements replacements;
	@Autowired private IdentityAuthentications authentications;
	@Autowired private IdentityBrowserSessions sessions;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		this.jdbc.sql("DELETE FROM iam_administrator").update();
		this.jdbc.sql("DELETE FROM iam_admin_bootstrap").update();
		for (String table : List.of("iam_totp_replacement", "iam_totp_recovery", "iam_mfa_recovery_code", "iam_mfa_recovery_limit",
				"iam_user_totp", "iam_totp_authentication_limit", "iam_browser_session_attributes", "iam_browser_session",
				"iam_password_authentication_limit", "iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap (singleton) VALUES (1)").update();
	}

	@Test
	void emptyDatabaseCanPrepareAndInitializeTheFirstAdministratorUsingExistingAccountWorkflows() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		assertThat(this.administrators.candidateId()).contains(userId);
		assertThat(this.users.findById(userId).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
		assertThat(count("iam_user")).isEqualTo(1); assertThat(count("iam_administrator")).isZero();
		assertThat(this.jdbc.sql("SELECT status = 'consumed' AND finished_at IS NOT NULL FROM iam_user_setup").query(Boolean.class).single()).isTrue();
		var preparation = this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow();
		var factor = preparation.enrollment().orElseThrow();
		assertThat(this.jdbc.sql("SELECT status FROM iam_user_totp").query(String.class).single()).isEqualTo("pending");
		var codes = this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor, step()), context()).orElseThrow();
		assertThat(codes.codes()).hasSize(10); assertThat(this.administrators.findByUserId(userId)).isPresent();
		assertThat(this.jdbc.sql("SELECT status FROM iam_user_totp").query(String.class).single()).isEqualTo("active");
		assertThat(this.jdbc.sql("SELECT initial_user_id = candidate_user_id AND completed_at IS NOT NULL FROM iam_admin_bootstrap")
				.query(Boolean.class).single()).isTrue();
		assertThat(events("admin_bootstrap_prepared")).hasSize(1);
		assertThat(events("admin_bootstrap_completed")).hasSize(1);
		assertThat(events("totp_enrollment_completed")).hasSize(1);
		assertThat(this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a").query(String.class).list().toString())
				.doesNotContain(PASSWORD, factor.secret());
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
	}

	@Test
	void restartResumesTheSameCandidateAndReplacesOnlyThePendingEnrollment() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var original = this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow();
		try (var restarted = restart(KEY_FILE.toString())) {
			var service = restarted.getBean(IdentityAdministrators.class);
			assertThat(service.candidateId()).contains(userId);
			var replacement = service.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow();
			assertThat(replacement.factorId()).isNotEqualTo(original.factorId());
			assertThat(replacement.secret()).isNotEqualTo(original.secret());
			assertThat(service.bootstrap(userId, original.factorId(), PASSWORD, otp(original, step()), context())).isEmpty();
			assertThat(service.bootstrap(userId, replacement.factorId(), PASSWORD, otp(replacement, step()), context())).isPresent();
		}
		assertThat(count("iam_user")).isEqualTo(1); assertThat(count("iam_administrator")).isEqualTo(1);
	}

	@Test
	void existingActiveFactorIsRetainedAndNeverDisclosedDuringPreparation() {
		var factor = activeFactor(activeUser("alice").id());
		var stored = this.jdbc.sql("SELECT row_to_json(t)::text FROM iam_user_totp t").query(String.class).single();
		assertThat(this.administrators.prepareCandidate(factor.userId(), PASSWORD, context()).orElseThrow().enrollment()).isEmpty();
		assertThat(this.administrators.candidateId()).contains(factor.userId());
		assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM iam_user_totp t").query(String.class).single()).isEqualTo(stored);
		assertThat(bootstrap(factor)).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "new", "existing", "missing-marker", "closed", "existing-administrator" })
	void candidateReservationAndClosurePreventAlternativeOrOrphanAccounts(String state) {
		UUID candidate = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = activeFactor(activeUser("bobby").id());
		if (state.equals("missing-marker")) { this.jdbc.sql("DELETE FROM iam_admin_bootstrap").update(); }
		if (state.equals("closed")) {
			var prepared = this.administrators.prepareCandidate(candidate, PASSWORD, context()).orElseThrow().enrollment().orElseThrow();
			this.administrators.bootstrap(candidate, prepared.factorId(), PASSWORD, otp(prepared, step()), context()).orElseThrow();
		}
		if (state.equals("existing-administrator")) { grantFixture(factor.userId()); }
		var before = snapshotWithoutAudit();
		assertThatThrownBy(() -> this.administrators.createCandidate("carol", "Carol", PASSWORD, SYSTEM)).isInstanceOf(RuntimeException.class);
		assertThat(snapshotWithoutAudit()).isEqualTo(before);
		if (state.equals("missing-marker")) {
			assertThatThrownBy(() -> this.administrators.prepareCandidate(factor.userId(), PASSWORD, context())).isInstanceOf(DataAccessException.class);
			assertThatThrownBy(() -> bootstrap(factor)).isInstanceOf(DataAccessException.class);
		}
		else {
			assertThat(this.administrators.prepareCandidate(factor.userId(), PASSWORD, context())).isEmpty();
			assertThat(bootstrap(factor)).isEmpty();
		}
		assertThat(snapshotWithoutAudit().getFirst()).isEqualTo(before.getFirst());
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "disabled", "expired", "wrong-factor", "wrong-code", "version" })
	void incompleteCandidateCannotActivateTheFactorOrObtainAdministratorQualification(String failure) {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow();
		if (failure.equals("disabled")) { this.states.disable(userId, SYSTEM); }
		if (failure.equals("expired")) { this.jdbc.sql("UPDATE iam_user_totp SET issued_at = clock_timestamp() - INTERVAL '11 minutes', expires_at = clock_timestamp() - INTERVAL '1 second'").update(); }
		if (failure.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
		assertThat(this.administrators.bootstrap(userId, failure.equals("wrong-factor") ? UUID.randomUUID() : factor.factorId(),
				failure.equals("password") ? "wrong" : PASSWORD, failure.equals("wrong-code") ? "bad" : otp(factor, step()), context())).isEmpty();
		assertThat(count("iam_administrator")).isZero(); assertThat(count("iam_mfa_recovery_code")).isZero();
		assertThat(this.jdbc.sql("SELECT status FROM iam_user_totp").query(String.class).single()).isEqualTo("pending");
		assertThat(this.administrators.candidateId()).contains(userId);
	}

	@ParameterizedTest
	@ValueSource(strings = { "initial_password_set", "account_setup_completed", "admin_bootstrap_prepared" })
	void preparationAuditFailureLeavesNoAccountOrReservedCandidate(String action) {
		var before = snapshot();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT admin_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try { assertThatThrownBy(() -> this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM)).isInstanceOf(DataAccessException.class); }
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT admin_test_reject").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "skip", "retain" })
	void suppressedCandidateReservationRollsBackAccountCreation(String failure) {
		var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION admin_test_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN "
				+ (failure.equals("skip") ? "NULL" : "OLD") + "; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER admin_test_candidate BEFORE UPDATE ON iam_admin_bootstrap FOR EACH ROW EXECUTE FUNCTION admin_test_candidate()").update();
			assertThatIllegalStateException().isThrownBy(() -> this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM));
		}
		finally { this.jdbc.sql("DROP FUNCTION admin_test_candidate() CASCADE").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "totp_enrollment_completed", "admin_bootstrap_completed" })
	void grantAuditFailureAlsoRollsBackActivationOfTheNewFactor(String action) {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow();
		var before = snapshot();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT admin_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try {
			assertThatThrownBy(() -> this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor, step()), context())).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT admin_test_reject").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void concurrentPreparationCreatesOnlyOneCandidateAndNoOrphanAccount() throws Exception {
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = List.of("alice", "bobby").stream().map(name -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.administrators.createCandidate(name, name, PASSWORD, SYSTEM); return true; }
				catch (IllegalStateException rejected) { return false; }
			})).toList();
			start.countDown(); int successes = 0;
			for (var task : tasks) { if (task.get(15, TimeUnit.SECONDS)) { successes++; } }
			assertThat(successes).isEqualTo(1);
		}
		assertThat(count("iam_user")).isEqualTo(1); assertThat(count("iam_password")).isEqualTo(1);
		assertThat(this.administrators.candidateId()).isPresent(); assertThat(count("iam_administrator")).isZero();
	}

	@Test
	void repeatedWrongPasswordsCannotReserveAnExistingAccountOrDiscloseAnEnrollment() {
		var user = activeUser("alice"); var factor = this.totps.beginEnrollment(user.id(), SYSTEM);
		String stored = this.jdbc.sql("SELECT row_to_json(t)::text FROM iam_user_totp t").query(String.class).single();
		for (int attempt = 0; attempt < 5; attempt++) {
			assertThat(this.administrators.prepareCandidate(user.id(), "wrong", context())).isEmpty();
		}
		assertThat(this.administrators.prepareCandidate(user.id(), PASSWORD, context())).isEmpty();
		assertThat(this.administrators.candidateId()).isEmpty();
		assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM iam_user_totp t").query(String.class).single()).isEqualTo(stored);
		assertThat(events("admin_bootstrap_prepared")).isEmpty();
		assertThat(events("admin_bootstrap_throttled")).hasSize(1);
		assertThat(factor.secret()).isNotBlank();
	}

	@Test
	void failedReenrollmentRetainsThePreviouslyCommittedCandidateAndPendingFactor() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow();
		var before = snapshot();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT admin_test_reject CHECK (action <> 'totp_enrollment_started') NOT VALID").update();
		try { assertThatThrownBy(() -> this.administrators.prepareCandidate(userId, PASSWORD, context())).isInstanceOf(DataAccessException.class); }
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT admin_test_reject").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void databaseCannotBindACompletedInitializationToADifferentCandidate() {
		var alice = activeFactor(activeUser("alice").id()); var bob = activeUser("bobby");
		bootstrap(alice).orElseThrow();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_admin_bootstrap SET candidate_user_id = :id").param("id", bob.id()).update())
				.isInstanceOf(DataAccessException.class);
	}

	@Test
	void preparationDoesNotStartWebOrScheduledInfrastructureAndItsContextClosesNormally() {
		var context = restart(KEY_FILE.toString());
		try (context) {
			assertThat(context).isNotInstanceOf(org.springframework.web.context.WebApplicationContext.class);
			assertThat(context.getBeansOfType(org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor.class)).isEmpty();
			assertThat(context.getBeansOfType(org.springframework.security.web.SecurityFilterChain.class)).isEmpty();
			assertThat(context.getBean(IdentityAdministrators.class).candidateId()).isEmpty();
		}
		assertThat(context.isActive()).isFalse();
	}

	@Test
	void invalidOrNestedPreparationDoesNotLeavePersistentChanges() {
		var before = snapshot();
		assertThatThrownBy(() -> this.administrators.createCandidate("alice", "Alice", "weak", SYSTEM)).isInstanceOf(IllegalArgumentException.class);
		assertThatIllegalArgumentException().isThrownBy(() -> this.administrators.prepareCandidate(null, PASSWORD, context()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.administrators.prepareCandidate(UUID.randomUUID(), PASSWORD, null));
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
			assertThatIllegalStateException().isThrownBy(() -> this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM));
			assertThatIllegalStateException().isThrownBy(() -> this.administrators.prepareCandidate(UUID.randomUUID(), PASSWORD, context()));
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void bootstrapCommitsIdentityClosureFreshRecoveryCodesAndOldAuthenticationRevocationTogether() {
		var alice = activeUser("alice"); var bob = activeUser("bobby"); var factor = activeFactor(alice.id());
		// Existing recovery codes are fixture state; the following operations verify fresh TOTP themselves.
		var oldCodes = new TransactionTemplate(this.transactions).execute(status ->
				this.recoveryCodes.issueForVerifiedFactor(alice.id(), factor.factorId(), SYSTEM));
		var pending = this.replacements.begin(alice.id(), PASSWORD, otp(factor, step()), context()).orElseThrow();
		var login = this.authentications.authenticate(alice.username(), PASSWORD, passwordContext()).orElseThrow();
		String hash = this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", alice.id()).query(String.class).single();
		addSession(alice.id()); addSession(bob.id());
		var bootstrapContext = context();
		String bootstrapCode = otp(factor, step() + 1);
		var result = this.administrators.bootstrap(alice.id(), PASSWORD, bootstrapCode, bootstrapContext).orElseThrow();
		assertThat(result.userId()).isEqualTo(alice.id()); assertThat(result.factorId()).isEqualTo(factor.factorId());
		assertThat(result.codes()).hasSize(10).doesNotContainAnyElementsOf(oldCodes.codes());
		assertThat(this.administrators.findByUserId(alice.id())).isPresent();
		assertThat(this.administrators.findByUserId(bob.id())).isEmpty();
		var marker = this.jdbc.sql("SELECT * FROM iam_admin_bootstrap").query().singleRow();
		assertThat(marker).containsEntry("initial_user_id", alice.id()).containsEntry("revision", 1L);
		assertThat(marker.get("completed_at")).isNotNull();
		assertThat(this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", alice.id()).query(String.class).single()).isEqualTo(hash);
		assertThat(this.sessions.isAuthenticationCurrent(alice.id(), System.currentTimeMillis(), login.credentialVersion())).isFalse();
		assertThat(this.jdbc.sql("SELECT principal_name FROM iam_browser_session").query(String.class).list()).containsExactly(bob.id().toString());
		assertThat(this.totps.verify(alice.id(), bootstrapCode, context())).isEmpty();
		assertThat(this.recoveryCodes.consume(alice.id(), oldCodes.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(this.replacements.complete(alice.id(), pending.replacementId(), pending.token(), otp(pending.enrollment(), step()), context())).isEmpty();
		var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE correlation_id = :id").param("id", bootstrapContext.correlationId()).query().listOfRows();
		assertThat(events.stream().map(e -> e.get("action"))).containsExactlyInAnyOrder("password_authenticated", "totp_authenticated", "browser_sessions_revoked", "mfa_recovery_codes_generated", "admin_bootstrap_completed");
		assertThat(events).allSatisfy(e -> assertThat(e).containsEntry("actor", "user:" + alice.id()));
		assertThat(events.toString()).doesNotContain(PASSWORD, factor.secret(), hash);
		for (String code : result.codes()) { assertThat(events.toString()).doesNotContain(code); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "null-password", "null-code", "code", "replay", "unknown", "disabled", "no-password", "pending-factor", "no-factor", "pending-user" })
	void invalidCredentialsAndUnreadyIdentitiesCannotInitializeAnAdministrator(String state) {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		if (state.equals("disabled")) { this.states.disable(user.id(), SYSTEM); }
		if (state.equals("no-password")) { this.jdbc.sql("DELETE FROM iam_password").update(); }
		if (state.equals("pending-user")) { this.jdbc.sql("UPDATE iam_user SET status = 'pending'").update(); }
		if (state.equals("pending-factor")) { this.jdbc.sql("UPDATE iam_user_totp SET status = 'pending', activated_at = NULL, last_used_step = NULL").update(); }
		if (state.equals("no-factor")) { this.jdbc.sql("DELETE FROM iam_user_totp").update(); }
		String code = otp(factor, step());
		if (state.equals("replay")) { assertThat(this.totps.verify(user.id(), code, context())).isPresent(); }
		assertThat(this.administrators.bootstrap(state.equals("unknown") ? UUID.randomUUID() : user.id(),
				state.equals("password") ? "wrong" : state.equals("null-password") ? null : PASSWORD,
				state.equals("code") ? "bad" : state.equals("null-code") ? null : code, context())).isEmpty();
		assertThat(count("iam_administrator")).isZero();
		assertThat(this.jdbc.sql("SELECT completed_at IS NULL FROM iam_admin_bootstrap").query(Boolean.class).single()).isTrue();
		assertThat(events("admin_bootstrap_completed")).isEmpty();
	}

	@Test
	void closureSurvivesRestartAndEvenTheLossOfAllAdministratorRows() {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		assertThat(bootstrap(factor)).isPresent();
		var stored = this.jdbc.sql("SELECT * FROM iam_admin_bootstrap").query().singleRow();
		this.jdbc.sql("DELETE FROM iam_administrator").update();
		try (var restarted = restart(KEY_FILE.toString())) {
			assertThat(restarted.getBean(IdentityAdministrators.class).bootstrap(user.id(), PASSWORD, otp(factor, step() + 1), context())).isEmpty();
		}
		assertThat(count("iam_administrator")).isZero();
		assertThat(this.jdbc.sql("SELECT * FROM iam_admin_bootstrap").query().singleRow()).isEqualTo(stored);
		assertThat(events("admin_bootstrap_completed")).hasSize(1);
		assertThat(events("admin_bootstrap_rejected")).hasSize(1);
	}

	@Test
	void preexistingAdministratorOrMissingLifecycleStateFailsClosed() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); grantFixture(user.id());
		assertThat(bootstrap(factor)).isEmpty();
		this.jdbc.sql("DELETE FROM iam_administrator").update(); this.jdbc.sql("DELETE FROM iam_admin_bootstrap").update();
		var before = snapshot();
		assertThatThrownBy(() -> bootstrap(factor)).isInstanceOf(DataAccessException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void concurrentInitializationCanGrantOnlyOneAdministrator(boolean sameUser) throws Exception {
		var alice = activeFactor(activeUser("alice").id());
		var bob = sameUser ? alice : activeFactor(activeUser("bobby").id());
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = List.of(alice, bob).stream().map(factor -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return bootstrap(factor).isPresent();
			})).toList();
			start.countDown(); int successes = 0;
			for (var task : tasks) { if (task.get(15, TimeUnit.SECONDS)) { successes++; } }
			assertThat(successes).isEqualTo(1);
		}
		assertThat(count("iam_administrator")).isEqualTo(1); assertThat(events("admin_bootstrap_completed")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "password_authenticated", "totp_authenticated", "browser_sessions_revoked", "mfa_recovery_codes_generated", "admin_bootstrap_completed" })
	void requiredAuditFailureRollsBackEveryBootstrapMutation(String action) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); addSession(user.id()); var before = snapshot();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT admin_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try { assertThatThrownBy(() -> bootstrap(factor)).isInstanceOf(DataAccessException.class); }
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT admin_test_reject").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void deferredCommitFailureDoesNotReturnCodesOrPersistTheGrantAndClosure() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION admin_test_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE CONSTRAINT TRIGGER admin_test_commit AFTER INSERT ON iam_administrator DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION admin_test_commit()").update();
			assertThatThrownBy(() -> bootstrap(factor)).isInstanceOf(TransactionSystemException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION admin_test_commit() CASCADE").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "marker-skipped", "marker-retained", "grant-skipped", "grant-retained", "version", "codes", "session" })
	void suppressedMandatoryWritesCannotReportSuccessfulInitialization(String fault) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); addSession(user.id()); var before = snapshot();
		String table = fault.startsWith("marker") ? "iam_admin_bootstrap" : fault.startsWith("grant") ? "iam_administrator"
				: fault.equals("version") ? "iam_password" : fault.equals("codes") ? "iam_mfa_recovery_code" : "iam_browser_session";
		String mutation = fault.startsWith("marker") || fault.equals("version") ? "UPDATE" : fault.equals("session") ? "DELETE" : "INSERT";
		String body = fault.equals("grant-retained") ? "NEW.granted_at := NEW.granted_at + INTERVAL '1 second'; RETURN NEW;"
				: fault.equals("marker-retained") || fault.equals("version") ? "RETURN OLD;" : "RETURN NULL;";
		this.jdbc.sql("CREATE FUNCTION admin_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER admin_test_suppress BEFORE " + mutation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION admin_test_suppress()").update();
			assertThatThrownBy(() -> bootstrap(factor)).isInstanceOf(RuntimeException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION admin_test_suppress() CASCADE").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void sharedTotpBudgetAndBlockedPasswordSourceBoundInitializationAttempts() {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		for (int i = 0; i < 5; i++) { assertThat(this.administrators.bootstrap(user.id(), PASSWORD, "bad", context())).isEmpty(); }
		assertThat(this.totps.verify(user.id(), otp(factor, step()), context())).isEmpty();
		assertThat(bootstrap(factor)).isEmpty(); assertThat(events("admin_bootstrap_throttled")).hasSize(1);
		this.jdbc.sql("DELETE FROM iam_totp_authentication_limit").update();
		for (int i = 0; i < 30; i++) { this.authentications.authenticate("missing-" + i, "bad", passwordContext()); }
		for (int i = 0; i < 40; i++) { this.administrators.bootstrap(UUID.randomUUID(), "bad", "bad", context()); }
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(30);
		assertThat(count("iam_administrator")).isZero();
	}

	@Test
	void ambientTransactionsAndMissingTrustedInputsAreRejectedWithoutWrites() {
		var factor = activeFactor(activeUser("alice").id()); var before = snapshot();
		assertThatIllegalArgumentException().isThrownBy(() -> this.administrators.bootstrap(null, PASSWORD, "123456", context()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.administrators.bootstrap(factor.userId(), PASSWORD, "123456", null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.administrators.findByUserId(null));
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> bootstrap(factor));
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "wrong" })
	void absentOrWrongProtectionKeyCannotInitializeAnAdministrator(String key) {
		var factor = activeFactor(activeUser("alice").id()); var before = snapshot();
		try (var restarted = restart(key.isEmpty() ? "" : keyFile().toString())) {
			assertThatIllegalStateException().isThrownBy(() -> restarted.getBean(IdentityAdministrators.class)
					.bootstrap(factor.userId(), PASSWORD, otp(factor, step()), context()));
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void lastAdministratorProtectionRetainsSessionsVersionAndAllCredentialMaterial() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); bootstrap(factor).orElseThrow(); addSession(user.id());
		var audit = new SecurityAuditContext("system:operator", "internal:test", UUID.randomUUID()); var before = snapshotWithoutAudit();
		assertThat(this.states.disable(user.id(), audit)).isEqualTo(IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
		assertThat(snapshotWithoutAudit()).isEqualTo(before);
		assertThat(events("last_administrator_protected")).hasSize(1);
		assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'last_administrator_protected'").query(String.class).single()).isEqualTo(audit.actor());
		assertThat(events("user_disabled")).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "ordinary", "disabled", "pending", "no-password", "pending-factor", "no-factor" })
	void unusableOrNonAdministratorPeersCannotSatisfyLastEntryProtection(String peerState) {
		var alice = activeUser("alice"); var bob = activeUser("bobby"); activeFactor(alice.id()); activeFactor(bob.id()); grantFixture(alice.id());
		if (!peerState.equals("ordinary")) { grantFixture(bob.id()); }
		if (peerState.equals("disabled") || peerState.equals("pending")) {
			this.jdbc.sql("UPDATE iam_user SET status = :status WHERE id = :id").param("id", bob.id()).param("status", peerState).update();
		}
		if (peerState.equals("no-password")) { this.jdbc.sql("DELETE FROM iam_password WHERE user_id = :id").param("id", bob.id()).update(); }
		if (peerState.equals("pending-factor")) { this.jdbc.sql("UPDATE iam_user_totp SET status = 'pending', activated_at = NULL, last_used_step = NULL WHERE user_id = :id").param("id", bob.id()).update(); }
		if (peerState.equals("no-factor")) { this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :id").param("id", bob.id()).update(); }
		assertThat(this.states.disable(alice.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
	}

	@Test
	void disablingOneOfTwoUsableAdministratorsPreservesMembershipAndTheFinalEntry() {
		var alice = activeUser("alice"); var bob = activeUser("bobby"); activeFactor(alice.id()); activeFactor(bob.id());
		grantFixture(alice.id()); grantFixture(bob.id());
		assertThat(this.states.disable(alice.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
		assertThat(this.administrators.findByUserId(alice.id())).isPresent();
		assertThat(this.states.disable(bob.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
		assertThat(this.states.enable(alice.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
		assertThat(this.states.disable(bob.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
	}

	@Test
	void concurrentDisablesCannotRemoveBothAdministrators() throws Exception {
		var alice = activeUser("alice"); var bob = activeUser("bobby"); activeFactor(alice.id()); activeFactor(bob.id());
		grantFixture(alice.id()); grantFixture(bob.id()); var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = List.of(alice, bob).stream().map(user -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return this.states.disable(user.id(), SYSTEM);
			})).toList(); start.countDown();
			var first = tasks.getFirst().get(15, TimeUnit.SECONDS); var second = tasks.getLast().get(15, TimeUnit.SECONDS);
			assertThat(List.of(first, second)).containsExactlyInAnyOrder(IdentityUserStates.Result.CHANGED, IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user WHERE status = 'active'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void repeatableReadCallerWithAnOldSnapshotCannotDisableTheRemainingEntry() throws Exception {
		var alice = activeUser("alice"); var bob = activeUser("bobby"); activeFactor(alice.id()); activeFactor(bob.id()); grantFixture(alice.id()); grantFixture(bob.id());
		var snapshotTaken = new CountDownLatch(1); var proceed = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var stale = executor.submit(() -> {
				var transaction = new TransactionTemplate(this.transactions); transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
				assertThatThrownBy(() -> transaction.executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT revision FROM iam_admin_bootstrap").query(Long.class).single(); snapshotTaken.countDown();
					try { assertThat(proceed.await(10, TimeUnit.SECONDS)).isTrue(); }
					catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
					this.states.disable(bob.id(), SYSTEM);
				})).isInstanceOf(DataAccessException.class);
			});
			try { assertThat(snapshotTaken.await(10, TimeUnit.SECONDS)).isTrue(); assertThat(this.states.disable(alice.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED); }
			finally { proceed.countDown(); }
			stale.get(15, TimeUnit.SECONDS);
		}
		assertThat(this.users.findById(bob.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
	}

	@Test
	void oldSnapshotCannotMissAJustCommittedAdministratorMembership() throws Exception {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		var snapshotTaken = new CountDownLatch(1); var proceed = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var stale = executor.submit(() -> {
				var transaction = new TransactionTemplate(this.transactions); transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
				assertThatThrownBy(() -> transaction.executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT count(*) FROM iam_administrator").query(Long.class).single(); snapshotTaken.countDown();
					try { assertThat(proceed.await(10, TimeUnit.SECONDS)).isTrue(); }
					catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
					this.states.disable(user.id(), SYSTEM);
				})).isInstanceOf(DataAccessException.class);
			});
			try { assertThat(snapshotTaken.await(10, TimeUnit.SECONDS)).isTrue(); assertThat(bootstrap(factor)).isPresent(); }
			finally { proceed.countDown(); }
			stale.get(15, TimeUnit.SECONDS);
		}
		assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
		assertThat(count("iam_administrator")).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void outerRollbackRestoresAllowedOrRejectedDisableIncludingLifecycleRevision(boolean hasPeer) {
		var alice = activeUser("alice"); activeFactor(alice.id()); grantFixture(alice.id());
		if (hasPeer) { var bob = activeUser("bobby"); activeFactor(bob.id()); grantFixture(bob.id()); }
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThat(this.states.disable(alice.id(), SYSTEM)).isEqualTo(hasPeer
					? IdentityUserStates.Result.CHANGED : IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
			tx.setRollbackOnly();
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "admin_bootstrap_rejected", "admin_bootstrap_throttled" })
	void requiredFailureAuditsCannotBeSilentlyLost(String action) {
		var factor = activeFactor(activeUser("alice").id());
		if (action.equals("admin_bootstrap_rejected")) { bootstrap(factor).orElseThrow(); }
		else { for (int i = 0; i < 5; i++) { this.administrators.bootstrap(factor.userId(), PASSWORD, "bad", context()); } }
		var before = snapshot();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT admin_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try { assertThatThrownBy(() -> bootstrap(factor)).isInstanceOf(DataAccessException.class); }
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT admin_test_reject").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void deniedProtectionAuditFailurePropagatesWithoutDisablingTheAdministrator() {
		var user = activeUser("alice"); activeFactor(user.id()); grantFixture(user.id()); var before = snapshot();
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT admin_test_reject CHECK (action <> 'last_administrator_protected') NOT VALID").update();
		try { assertThatThrownBy(() -> this.states.disable(user.id(), SYSTEM)).isInstanceOf(DataAccessException.class); }
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT admin_test_reject").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void revisionSuppressionRollsBackThePermittedDisable() {
		var alice = activeUser("alice"); var bob = activeUser("bobby"); activeFactor(alice.id()); activeFactor(bob.id()); grantFixture(alice.id()); grantFixture(bob.id());
		var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION admin_test_revision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER admin_test_revision BEFORE UPDATE ON iam_admin_bootstrap FOR EACH ROW EXECUTE FUNCTION admin_test_revision()").update();
			assertThatIllegalStateException().isThrownBy(() -> this.states.disable(alice.id(), SYSTEM));
		}
		finally { this.jdbc.sql("DROP FUNCTION admin_test_revision() CASCADE").update(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void waitingForTheUserLockRechecksDisabledStatusBeforeGranting() throws Exception {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.lockById(user.id()); locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				this.states.disable(user.id(), SYSTEM);
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue(); var initializing = executor.submit(() -> bootstrap(factor));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0)").query(Boolean.class).single());
				release.countDown(); blocker.get(10, TimeUnit.SECONDS); assertThat(initializing.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
		assertThat(count("iam_administrator")).isZero();
	}

	@Test
	void upgradingV15RetainsExistingRowsAndCreatesNoAdministratorOrClosedMarker() throws Exception {
		String schema = "admin_upgrade_" + UUID.randomUUID().toString().replace("-", ""); this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			var client = JdbcClient.create(new SingleConnectionDataSource(connection, true)); client.sql("SET search_path TO " + schema).update();
			flyway(schema, "15").migrate(); UUID user = UUID.randomUUID();
			client.sql("INSERT INTO iam_user (id,username,display_name,status) VALUES (:id,'alice','Alice','pending')").param("id", user).update();
			var oldTables = TABLES.stream().filter(t -> !t.equals("iam_administrator") && !t.equals("iam_admin_bootstrap")).toList(); var before = snapshot(client, oldTables);
			flyway(schema, "16").migrate(); flyway(schema, "16").migrate();
			assertThat(snapshot(client, oldTables)).isEqualTo(before);
			assertThat(client.sql("SELECT count(*) FROM iam_administrator").query(Long.class).single()).isZero();
			assertThat(client.sql("SELECT completed_at IS NULL AND initial_user_id IS NULL AND revision = 0 FROM iam_admin_bootstrap").query(Boolean.class).single()).isTrue();
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "singleton = 2", "revision = -1", "completed_at = clock_timestamp()", "initial_user_id = gen_random_uuid()", "candidate_user_id = gen_random_uuid()" })
	void databaseRejectsInvalidBootstrapState(String assignment) {
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_admin_bootstrap SET " + assignment).update()).isInstanceOf(DataAccessException.class);
	}

	private java.util.Optional<com.ixayda.iam.model.MfaRecoveryCodeSet> bootstrap(IdentityTotpEnrollment factor) {
		return this.administrators.bootstrap(factor.userId(), PASSWORD, otp(factor, step()), context());
	}

	private void grantFixture(UUID userId) {
		// Additional memberships model future management operations without exposing an unprotected grant API.
		this.jdbc.sql("INSERT INTO iam_administrator (user_id) VALUES (:id)").param("id", userId).update();
	}

	private IdentityUser activeUser(String username) {
		var user = this.users.create(username, "Private Name", SYSTEM); var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID()); return this.users.findById(user.id()).orElseThrow();
	}

	private IdentityTotpEnrollment activeFactor(UUID userId) {
		for (int attempt = 0; attempt < 10; attempt++) {
			var factor = this.totps.beginEnrollment(userId, SYSTEM); long step = step();
			if (Stream.of(step - 1, step, step + 1, step + 2).map(value -> otp(factor, value)).distinct().count() == 4) {
				this.jdbc.sql("UPDATE iam_user_totp SET status = 'active', activated_at = issued_at, last_used_step = :step WHERE user_id = :id")
						.param("step", step - 1).param("id", userId).update(); return factor;
			}
		}
		throw new AssertionError("Cannot create distinct TOTP fixture codes");
	}

	private void addSession(UUID userId) {
		String id = UUID.randomUUID().toString(); long now = System.currentTimeMillis();
		this.jdbc.sql("INSERT INTO iam_browser_session VALUES (:id, :id, :now, :now, 1800, :expiry, :principal)")
				.param("id", id).param("now", now).param("expiry", now + 1800000).param("principal", userId.toString()).update();
	}

	private org.springframework.context.ConfigurableApplicationContext restart(String key) {
		return new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword())).run("--iam.totp.key-file=" + key);
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

	private List<List<String>> snapshot() { return snapshot(this.jdbc, TABLES); }
	private List<List<String>> snapshotWithoutAudit() { return snapshot(this.jdbc, TABLES.stream().filter(t -> !t.equals("iam_security_audit")).toList()); }
	private static List<List<String>> snapshot(JdbcClient client, List<String> tables) {
		return tables.stream().map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
	}
	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }
	private List<Map<String, Object>> events(String action) { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = :action").param("action", action).query().listOfRows(); }
	private static long step() { return Math.floorDiv(Instant.now().getEpochSecond(), 30); }
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("deployment:test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static PasswordAuthenticationContext passwordContext() { var ctx = context(); return new PasswordAuthenticationContext(ctx.source(), ctx.clientAddress(), ctx.correlationId()); }
	private static MfaRecoveryCodeContext recoveryContext() { var ctx = context(); return new MfaRecoveryCodeContext(ctx.source(), ctx.clientAddress(), ctx.correlationId()); }

	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-admin-test-", ".key"); byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
			Files.write(path, bytes); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}

	private static String otp(IdentityTotpEnrollment enrollment, long step) {
		byte[] counter = new byte[8]; for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(enrollment.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(java.util.Locale.ROOT, "%06d", number % 1_000_000);
	}

}
