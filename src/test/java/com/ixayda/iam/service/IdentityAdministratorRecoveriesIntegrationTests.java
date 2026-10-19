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
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityAdministratorRecovery;
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
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAdministratorRecoveriesIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:fixture", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();

	@Autowired private IdentityAdministratorRecoveries recoveries;
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityTotpRecoveries normalRecoveries;
	@Autowired private IdentityTotpReplacements replacements;
	@Autowired private IdentityAuthentications authentications;
	@Autowired private IdentityBrowserSessions sessions;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap (singleton) VALUES (1)").update();
	}

	@Test
	void preparationKeepsTheExistingEntryAndStoresOnlyBoundProtectedMaterial() {
		var factor = administrator(); UUID userId = factor.userId(); addSession(userId);
		var before = snapshotExcept("iam_administrator_recovery", "iam_security_audit", "iam_totp_authentication_limit", "iam_password_authentication_limit");
		var audit = deployment(); var recovery = this.recoveries.begin(userId, PASSWORD, audit).orElseThrow();
		assertThat(snapshotExcept("iam_administrator_recovery", "iam_security_audit", "iam_totp_authentication_limit", "iam_password_authentication_limit")).isEqualTo(before);
		var row = this.jdbc.sql("SELECT * FROM iam_administrator_recovery").query().singleRow();
		assertThat(row.get("old_factor_id")).isEqualTo(factor.factorId());
		assertThat(row.get("new_factor_id")).isEqualTo(recovery.enrollment().factorId());
		assertThat(row.get("actor")).isEqualTo(audit.actor()); assertThat(row.get("source")).isEqualTo(audit.source());
		assertThat(row.get("correlation_id")).isEqualTo(audit.correlationId());
		assertThat(row.get("token_digest")).asString().matches("[0-9a-f]{64}").isNotEqualTo(recovery.token());
		assertThat(row.get("secret_ciphertext")).asString().startsWith("v1.").doesNotContain(recovery.enrollment().secret());
		assertThat(recovery.enrollment().expiresAt()).isBetween(Instant.now().plusSeconds(590), Instant.now().plusSeconds(601));
		assertThat(recovery.toString()).doesNotContain(recovery.token(), recovery.enrollment().secret(), recovery.enrollment().provisioningUri());
		assertAuditDoesNotContain(PASSWORD, recovery.token(), recovery.enrollment().secret(), recovery.enrollment().provisioningUri());
		assertThat(events("admin_recovery_started")).hasSize(1);
	}

	@Test
	void completionReplacesTheFactorAndCredentialsAtomicallyWithoutChangingTheAdministratorIdentity() {
		var factor = administrator(); UUID userId = factor.userId();
		var other = activeUser("bobby"); addSession(userId); addSession(userId); addSession(other.id());
		var membership = rows("iam_administrator");
		var initial = this.jdbc.sql("SELECT completed_at, initial_user_id, candidate_user_id FROM iam_admin_bootstrap").query().singleRow();
		long revision = this.jdbc.sql("SELECT revision FROM iam_admin_bootstrap").query(Long.class).single();
		long version = version(userId); String hash = this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", userId).query(String.class).single();
		var audit = deployment(); var recovery = this.recoveries.begin(userId, PASSWORD, audit).orElseThrow();
		String code = otp(recovery.enrollment(), step());
		var result = this.recoveries.complete(userId, recovery.recoveryId(), recovery.token(), PASSWORD, code, audit).orElseThrow();
		assertThat(result.codes()).hasSize(10).doesNotHaveDuplicates(); assertThat(result.factorId()).isEqualTo(recovery.enrollment().factorId());
		assertThat(version(userId)).isEqualTo(version + 1); assertThat(rows("iam_administrator")).isEqualTo(membership);
		assertThat(this.jdbc.sql("SELECT completed_at, initial_user_id, candidate_user_id FROM iam_admin_bootstrap").query().singleRow()).isEqualTo(initial);
		assertThat(this.jdbc.sql("SELECT revision FROM iam_admin_bootstrap").query(Long.class).single()).isEqualTo(revision + 1);
		assertThat(this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", userId).query(String.class).single()).isEqualTo(hash);
		assertThat(count("iam_administrator_recovery")).isZero(); assertThat(count("iam_mfa_recovery_code")).isEqualTo(10);
		assertThat(this.jdbc.sql("SELECT principal_name FROM iam_browser_session").query(String.class).list()).containsExactly(other.id().toString());
		assertThat(this.users.hasCurrentPasswordVersion(userId, version)).isFalse();
		assertThat(this.totps.verify(userId, code, authentication())).isEmpty();
		assertThat(this.recoveries.complete(userId, recovery.recoveryId(), recovery.token(), PASSWORD, code, audit)).isEmpty();
		assertThat(this.states.disable(userId, SYSTEM)).isEqualTo(IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
		assertThat(events("admin_recovery_completed")).hasSize(1).allSatisfy(event -> {
			assertThat(event.get("actor")).isEqualTo(audit.actor()); assertThat(event.get("source")).isEqualTo(audit.source());
			assertThat(event.get("correlation_id")).isEqualTo(audit.correlationId());
		});
		assertAuditDoesNotContain(PASSWORD, recovery.token(), recovery.enrollment().secret(), result.codes().getFirst());
	}

	@Test
	void aNewAuthorizedAttemptInvalidatesThePreviouslyDeliveredPreparation() {
		var factor = administrator(); var audit = deployment();
		var old = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		var current = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		assertThat(current.recoveryId()).isNotEqualTo(old.recoveryId());
		assertThat(this.recoveries.complete(factor.userId(), old.recoveryId(), old.token(), PASSWORD, otp(old.enrollment(), step()), audit)).isEmpty();
		assertThat(this.recoveries.complete(factor.userId(), current.recoveryId(), current.token(), PASSWORD, otp(current.enrollment(), step()), audit)).isPresent();
	}

	@Test
	void pendingRecoverySurvivesRestartAndDoesNotStartWebOrScheduledInfrastructure() {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		var restarted = restart(Map.of());
		try {
			assertThat(restarted).isNotInstanceOf(WebApplicationContext.class);
			assertThat(restarted.getBeansOfType(ScheduledAnnotationBeanPostProcessor.class)).isEmpty();
			assertThat(restarted.getBeansOfType(org.springframework.security.web.SecurityFilterChain.class)).isEmpty();
			assertThat(restarted.getBean(IdentityAdministratorRecoveries.class).complete(factor.userId(), pending.recoveryId(), pending.token(),
					PASSWORD, otp(pending.enrollment(), step()), audit)).isPresent();
		}
		finally { restarted.close(); }
		assertThat(restarted.isActive()).isFalse();
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
	}

	@ParameterizedTest
	@ValueSource(strings = { "unknown", "ordinary-user", "pending-user", "disabled", "password", "missing-password", "missing-factor", "pending-factor", "open-bootstrap" })
	void preparationCannotCreateOrReactivateAnAdministrator(String failure) {
		var factor = administrator(); UUID userId = factor.userId();
		switch (failure) {
			case "unknown" -> userId = UUID.randomUUID();
			case "ordinary-user" -> userId = activeUser("bobby").id();
			case "pending-user" -> userId = this.users.create("bobby", "Bob", SYSTEM).id();
			case "disabled" -> this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", userId).update();
			case "missing-password" -> this.jdbc.sql("DELETE FROM iam_password WHERE user_id = :id").param("id", userId).update();
			case "missing-factor" -> this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :id").param("id", userId).update();
			case "pending-factor" -> this.jdbc.sql("UPDATE iam_user_totp SET status = 'pending', activated_at = NULL, last_used_step = NULL").update();
			case "open-bootstrap" -> this.jdbc.sql("UPDATE iam_admin_bootstrap SET completed_at = NULL, initial_user_id = NULL").update();
			default -> { }
		}
		var before = durableState();
		assertThat(this.recoveries.begin(userId, failure.equals("password") ? "incorrect" : PASSWORD, deployment())).isEmpty();
		assertThat(durableState()).isEqualTo(before); assertThat(events("admin_recovery_rejected")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "code", "expired", "id", "token", "malformed-token", "null-token", "version", "membership", "disabled", "actor", "reference", "correlation" })
	void completionRejectsStaleOrMisboundMaterialWithoutChangingTheExistingEntry(String failure) {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		if (failure.equals("expired")) { expire(factor.userId()); }
		if (failure.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
		if (failure.equals("membership")) { this.jdbc.sql("DELETE FROM iam_administrator").update(); }
		if (failure.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled'").update(); }
		var invocation = switch (failure) {
			case "actor" -> new SecurityAuditContext("deployment:other", audit.source(), audit.correlationId());
			case "reference" -> new SecurityAuditContext(audit.actor(), "deployment:admin-recovery:OTHER", audit.correlationId());
			case "correlation" -> new SecurityAuditContext(audit.actor(), audit.source(), UUID.randomUUID());
			default -> audit;
		};
		String token = switch (failure) { case "token" -> "A".repeat(43); case "malformed-token" -> "invalid"; case "null-token" -> null; default -> pending.token(); };
		var before = durableState();
		assertThat(this.recoveries.complete(factor.userId(), failure.equals("id") ? UUID.randomUUID() : pending.recoveryId(), token,
				failure.equals("password") ? "incorrect" : PASSWORD, failure.equals("code") ? "invalid" : otp(pending.enrollment(), step()), invocation)).isEmpty();
		assertThat(durableState()).isEqualTo(before); assertThat(events("admin_recovery_completed")).isEmpty();
		assertThat(events("admin_recovery_rejected")).hasSize(1);
	}

	@Test
	void proofsCannotBeConsumedByAnotherIdentityOrTheOrdinaryRecoveryAndReplacementServices() {
		var factor = administrator(); var other = activeUser("bobby"); var audit = deployment();
		var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		String code = otp(pending.enrollment(), step()); var before = durableState();
		assertThat(this.recoveries.complete(other.id(), pending.recoveryId(), pending.token(), PASSWORD, code, audit)).isEmpty();
		assertThat(this.normalRecoveries.complete(factor.userId(), pending.recoveryId(), pending.token(), code, authentication())).isEmpty();
		assertThat(this.replacements.complete(factor.userId(), pending.recoveryId(), pending.token(), code, authentication())).isEmpty();
		assertThat(durableState()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "ordinary-recovery", "replacement" })
	void completingAnotherFactorWorkflowInvalidatesDeploymentPreparation(String workflow) {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		if (workflow.equals("replacement")) {
			var replacement = this.replacements.begin(factor.userId(), PASSWORD, otp(factor, step() + 1), authentication()).orElseThrow();
			this.replacements.complete(factor.userId(), replacement.replacementId(), replacement.token(), otp(replacement.enrollment(), step()), authentication()).orElseThrow();
		}
		else {
			var codes = this.recoveryCodes.issue(factor.userId(), otp(factor, step() + 1), authentication()).orElseThrow();
			var ordinary = this.normalRecoveries.begin(factor.userId(), PASSWORD, codes.codes().getFirst(),
					new com.ixayda.iam.model.MfaRecoveryCodeContext("internal:test", InetAddress.getLoopbackAddress(), UUID.randomUUID())).orElseThrow();
			this.normalRecoveries.complete(factor.userId(), ordinary.recoveryId(), ordinary.token(), otp(ordinary.enrollment(), step()), authentication()).orElseThrow();
		}
		assertThat(count("iam_administrator_recovery")).isZero();
		assertThat(this.recoveries.complete(factor.userId(), pending.recoveryId(), pending.token(), PASSWORD, otp(pending.enrollment(), step()), audit)).isEmpty();
	}

	@Test
	void accountFailuresAreSharedWithNormalTotpAndCannotBeResetByPreparingAnotherRecovery() {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		for (int i = 0; i < 5; i++) { assertThat(this.totps.verify(factor.userId(), "invalid", authentication())).isEmpty(); }
		var before = durableState();
		assertThat(this.recoveries.begin(factor.userId(), PASSWORD, deployment())).isEmpty();
		assertThat(this.recoveries.complete(factor.userId(), pending.recoveryId(), pending.token(), PASSWORD, otp(pending.enrollment(), step()), audit)).isEmpty();
		assertThat(events("admin_recovery_throttled")).hasSize(2); assertThat(durableState()).isEqualTo(before);
	}

	@Test
	void passwordFailuresRespectTheExistingPasswordBudget() {
		var factor = administrator();
		for (int i = 0; i < 10; i++) { this.authentications.authenticate("alice", "invalid", passwordAuthentication()); }
		var before = durableState();
		assertThat(this.recoveries.begin(factor.userId(), PASSWORD, deployment())).isEmpty();
		assertThat(durableState()).isEqualTo(before); assertThat(events("password_auth_throttled")).hasSize(1);
	}

	@Test
	void changingTheOperatorOrReferenceCannotPartitionTheSharedSourceBudget() {
		var factor = administrator();
		for (int i = 0; i < 30; i++) {
			var audit = new SecurityAuditContext("deployment:operator-" + i, "deployment:admin-recovery:CHANGE-" + i, UUID.randomUUID());
			assertThat(this.recoveries.begin(UUID.randomUUID(), "invalid", audit)).isEmpty();
		}
		long accountBuckets = this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single();
		var before = durableState();
		assertThat(this.recoveries.begin(factor.userId(), PASSWORD, deployment())).isEmpty();
		assertThat(this.recoveries.begin(UUID.randomUUID(), PASSWORD, deployment())).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_totp_authentication_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(accountBuckets);
		assertThat(events("admin_recovery_throttled")).hasSize(2); assertThat(durableState()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "pending-write", "pending-retained", "audit", "silent-audit", "deferred-audit", "expired" })
	void preparationStorageOrAuditFailureDoesNotDeliverOrPersistARecovery(String fault) {
		var factor = administrator();
		if (fault.equals("pending-retained")) { this.recoveries.begin(factor.userId(), PASSWORD, deployment()).orElseThrow(); }
		var before = snapshot();
		String table = fault.startsWith("pending") || fault.equals("expired") ? "iam_administrator_recovery" : "iam_security_audit";
		String operation = fault.equals("pending-retained") ? "UPDATE" : "INSERT";
		String body = switch (fault) {
			case "pending-write" -> "RETURN NULL;";
			case "pending-retained" -> "RETURN OLD;";
			case "expired" -> "NEW.issued_at := clock_timestamp() - INTERVAL '11 minutes'; NEW.expires_at := NEW.issued_at + INTERVAL '10 minutes'; RETURN NEW;";
			case "silent-audit" -> "IF NEW.action = 'admin_recovery_started' THEN RETURN NULL; END IF; RETURN NEW;";
			default -> "IF NEW.action = 'admin_recovery_started' THEN RAISE EXCEPTION 'test persistence failure'; END IF; RETURN NEW;";
		};
		installFault(table, operation, body, fault.equals("deferred-audit"));
		try { assertThatThrownBy(() -> this.recoveries.begin(factor.userId(), PASSWORD, deployment())).isInstanceOf(RuntimeException.class); }
		finally { removeFault(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "proof", "factor-delete", "factor-insert", "version", "revision", "session", "codes", "audit", "silent-audit", "deferred-audit" })
	void completionStorageOrAuditFailureRollsBackEverySecurityChange(String fault) {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow(); addSession(factor.userId());
		var before = snapshot();
		String table = switch (fault) {
			case "proof" -> "iam_administrator_recovery"; case "factor-delete", "factor-insert" -> "iam_user_totp";
			case "version" -> "iam_password"; case "revision" -> "iam_admin_bootstrap";
			case "session" -> "iam_browser_session"; case "codes" -> "iam_mfa_recovery_code"; default -> "iam_security_audit";
		};
		String operation = switch (fault) {
			case "proof", "factor-delete", "session" -> "DELETE";
			case "version", "revision" -> "UPDATE"; default -> "INSERT";
		};
		String body = switch (fault) {
			case "audit", "deferred-audit" -> "IF NEW.action = 'admin_recovery_completed' THEN RAISE EXCEPTION 'test persistence failure'; END IF; RETURN NEW;";
			case "silent-audit" -> "IF NEW.action = 'admin_recovery_completed' THEN RETURN NULL; END IF; RETURN NEW;";
			case "version", "revision" -> "RETURN OLD;"; default -> "RETURN NULL;";
		};
		installFault(table, operation, body, fault.equals("deferred-audit"));
		try { assertThatThrownBy(() -> complete(pending, audit)).isInstanceOf(RuntimeException.class); }
		finally { removeFault(); }
		assertThat(snapshot()).isEqualTo(before);
		assertThat(complete(pending, audit)).isPresent();
	}

	@Test
	void completionRechecksTheDeadlineAfterRequiredAuditPersistence() {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		this.jdbc.sql("WITH instant AS MATERIALIZED (SELECT clock_timestamp() + INTERVAL '1 second' AS expiry) UPDATE iam_administrator_recovery SET expires_at = expiry, issued_at = expiry - INTERVAL '10 minutes' FROM instant").update();
		var before = snapshot();
		installFault("iam_security_audit", "INSERT", "IF NEW.action = 'admin_recovery_completed' THEN PERFORM pg_sleep(1.2); END IF; RETURN NEW;", false);
		try { assertThatIllegalStateException().isThrownBy(() -> complete(pending, audit)); }
		finally { removeFault(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "rejected", "throttled" })
	void requiredFailureAuditErrorsPropagateAndRollBackFailureCounters(String denial) {
		var factor = administrator();
		if (denial.equals("throttled")) { for (int i = 0; i < 5; i++) { this.totps.verify(factor.userId(), "invalid", authentication()); } }
		var before = snapshot();
		installFault("iam_security_audit", "INSERT", "IF NEW.action = 'admin_recovery_" + denial + "' THEN RETURN NULL; END IF; RETURN NEW;", false);
		try { assertThatIllegalStateException().isThrownBy(() -> this.recoveries.begin(factor.userId(), "invalid", deployment())); }
		finally { removeFault(); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void concurrentCompletionCanDeliverExactlyOneNewCodeSet() throws Exception {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var calls = Stream.of(1, 2).map(ignored -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return complete(pending, audit);
			})).toList();
			start.countDown();
			assertThat(List.of(calls.getFirst().get(15, TimeUnit.SECONDS), calls.getLast().get(15, TimeUnit.SECONDS)))
					.filteredOn(java.util.Optional::isPresent).hasSize(1);
		}
		assertThat(count("iam_mfa_recovery_code")).isEqualTo(10); assertThat(events("admin_recovery_completed")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "version", "membership", "deadline" })
	void waitingForTheUserLockRechecksTheCurrentState(String change) throws Exception {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.lockById(factor.userId()); locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				switch (change) {
					case "version" -> this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update();
					case "membership" -> this.jdbc.sql("DELETE FROM iam_administrator").update();
					default -> expire(factor.userId());
				}
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue(); var completing = executor.submit(() -> complete(pending, audit));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0)").query(Boolean.class).single());
				release.countDown(); blocker.get(10, TimeUnit.SECONDS); assertThat(completing.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
		assertThat(events("admin_recovery_completed")).isEmpty();
	}

	@Test
	void aRestrictedDatabaseIdentityCannotInvokeEitherDeploymentStep() {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		String role = "recovery_role_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + role).update();
			var before = snapshot();
			try (var restricted = restart(Map.of("spring.flyway.enabled", "false", "spring.datasource.hikari.connection-init-sql", "SET ROLE " + role))) {
				var service = restricted.getBean(IdentityAdministratorRecoveries.class);
				assertThatIllegalStateException().isThrownBy(() -> service.begin(factor.userId(), PASSWORD, audit));
				assertThatIllegalStateException().isThrownBy(() -> service.complete(factor.userId(), pending.recoveryId(), pending.token(), PASSWORD, otp(pending.enrollment(), step()), audit));
			}
			assertThat(snapshot()).isEqualTo(before);
		}
		finally { this.jdbc.sql("DROP OWNED BY " + role).update(); this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing-key", "wrong-key" })
	void keyFailuresNeverConsumeTheRecoveryOrChangeTheCurrentFactor(String failure) {
		var factor = administrator(); var audit = deployment(); var pending = this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow(); var before = snapshot();
		try (var restarted = restart(Map.of("iam.totp.key-file", failure.equals("missing-key") ? "" : keyFile().toString()))) {
			assertThatIllegalStateException().isThrownBy(() -> restarted.getBean(IdentityAdministratorRecoveries.class)
					.complete(factor.userId(), pending.recoveryId(), pending.token(), PASSWORD, otp(pending.enrollment(), step()), audit));
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void ambientTransactionsAndUntrustedAttributionAreRejectedBeforeAnyMutation() {
		var factor = administrator(); var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> this.recoveries.begin(factor.userId(), PASSWORD, deployment()));
			assertThatIllegalStateException().isThrownBy(() -> this.recoveries.complete(factor.userId(), UUID.randomUUID(), "invalid", PASSWORD, "123456", deployment()));
		});
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.begin(factor.userId(), PASSWORD, SYSTEM));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void expiredCleanupRetainsTheActiveFactorAndValidPendingRows() {
		var factor = administrator(); var audit = deployment(); this.recoveries.begin(factor.userId(), PASSWORD, audit).orElseThrow();
		var before = durableState(); this.recoveries.cleanUpExpiredRecoveries(); assertThat(durableState()).isEqualTo(before);
		expire(factor.userId()); var factorRows = rows("iam_user_totp"); this.recoveries.cleanUpExpiredRecoveries();
		assertThat(count("iam_administrator_recovery")).isZero(); assertThat(rows("iam_user_totp")).isEqualTo(factorRows);
	}

	@ParameterizedTest
	@ValueSource(strings = { "new_factor_id = old_factor_id", "credential_version = 0", "token_digest = 'invalid'", "secret_ciphertext = 'plaintext'", "key_id = 'invalid'",
			"actor = 'user:somebody'", "source = 'browser:recovery'", "expires_at = issued_at + INTERVAL '11 minutes'" })
	void databaseRejectsMalformedRecoveryState(String assignment) {
		var factor = administrator(); this.recoveries.begin(factor.userId(), PASSWORD, deployment()).orElseThrow(); var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_administrator_recovery SET " + assignment).update()).isInstanceOf(DataAccessException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradingV19PreservesExistingIdentityAuditAndBootstrapState() throws Exception {
		String schema = "admin_recovery_upgrade_" + UUID.randomUUID().toString().replace("-", ""); this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			var client = JdbcClient.create(new SingleConnectionDataSource(connection, true)); client.sql("SET search_path TO " + schema).update();
			flyway(schema, "19").migrate(); UUID userId = UUID.randomUUID();
			client.sql("INSERT INTO iam_user (id, username, display_name, status) VALUES (:id, 'alice', 'Alice', 'pending')").param("id", userId).update();
			client.sql("INSERT INTO iam_administrator (user_id) VALUES (:id)").param("id", userId).update();
			client.sql("UPDATE iam_admin_bootstrap SET initial_user_id = :id, completed_at = clock_timestamp()").param("id", userId).update();
			client.sql("INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome) VALUES (gen_random_uuid(), 'deployment:original', 'deployment:admin-bootstrap', gen_random_uuid(), :id, 'admin_bootstrap_completed', 'success')")
					.param("id", userId).update();
			var before = List.of("iam_user", "iam_administrator", "iam_admin_bootstrap", "iam_security_audit").stream()
					.map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
			flyway(schema, "20").migrate(); assertThat(flyway(schema, "20").migrate().migrationsExecuted).isZero();
			assertThat(List.of("iam_user", "iam_administrator", "iam_admin_bootstrap", "iam_security_audit").stream()
					.map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList()).isEqualTo(before);
			assertThat(client.sql("SELECT count(*) FROM iam_administrator_recovery").query(Long.class).single()).isZero();
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private java.util.Optional<com.ixayda.iam.model.MfaRecoveryCodeSet> complete(IdentityAdministratorRecovery pending, SecurityAuditContext audit) {
		return this.recoveries.complete(pending.userId(), pending.recoveryId(), pending.token(), PASSWORD, otp(pending.enrollment(), step()), audit);
	}

	private IdentityTotpEnrollment administrator() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(userId, PASSWORD, authentication()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor, step()), authentication()).orElseThrow(); return factor;
	}

	private IdentityUser activeUser(String username) {
		var user = this.users.create(username, "Private Name", SYSTEM); var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID()); return this.users.findById(user.id()).orElseThrow();
	}

	private void addSession(UUID userId) {
		String id = UUID.randomUUID().toString(); long now = System.currentTimeMillis();
		this.jdbc.sql("INSERT INTO iam_browser_session VALUES (:id, :id, :now, :now, 1800, :expiry, :principal)")
				.param("id", id).param("now", now).param("expiry", now + 1_800_000).param("principal", userId.toString()).update();
	}

	private void expire(UUID userId) {
		this.jdbc.sql("UPDATE iam_administrator_recovery SET issued_at = '2026-01-01T00:00:00Z', expires_at = '2026-01-01T00:10:00Z' WHERE user_id = :id")
				.param("id", userId).update();
	}

	private void installFault(String table, String operation, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION admin_recovery_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		String trigger = deferred ? "CREATE CONSTRAINT TRIGGER admin_recovery_fault AFTER " + operation + " ON " + table + " DEFERRABLE INITIALLY DEFERRED"
				: "CREATE TRIGGER admin_recovery_fault BEFORE " + operation + " ON " + table;
		this.jdbc.sql(trigger + " FOR EACH ROW EXECUTE FUNCTION admin_recovery_fault()").update();
	}

	private void removeFault() { this.jdbc.sql("DROP FUNCTION admin_recovery_fault() CASCADE").update(); }
	private long version(UUID userId) { return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", userId).query(Long.class).single(); }
	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }
	private List<String> rows(String table) { return this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list(); }
	private List<List<String>> snapshot() { return snapshotExcept(); }
	private List<List<String>> durableState() {
		return snapshotExcept("iam_security_audit", "iam_password_authentication_limit", "iam_totp_authentication_limit", "iam_mfa_recovery_limit");
	}
	private List<List<String>> snapshotExcept(String... excluded) {
		return this.jdbc.sql("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND starts_with(table_name, 'iam_') ORDER BY table_name")
				.query(String.class).list().stream().filter(table -> !List.of(excluded).contains(table)).map(this::rows).toList();
	}
	private List<Map<String, Object>> events(String action) { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = :action").param("action", action).query().listOfRows(); }
	private void assertAuditDoesNotContain(String... secrets) { assertThat(rows("iam_security_audit").toString()).doesNotContain(secrets); }
	private static SecurityAuditContext deployment() { return new SecurityAuditContext("deployment:operator", "deployment:admin-recovery:CHANGE-123", UUID.randomUUID()); }
	private static TotpAuthenticationContext authentication() { return new TotpAuthenticationContext("internal:test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static PasswordAuthenticationContext passwordAuthentication() { return new PasswordAuthenticationContext("internal:test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static long step() { return Math.floorDiv(Instant.now().getEpochSecond(), 30); }

	private ConfigurableApplicationContext restart(Map<String, String> overrides) {
		var properties = new java.util.HashMap<String, Object>(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(),
				"spring.datasource.username", this.postgres.getUsername(), "spring.datasource.password", this.postgres.getPassword(),
				"iam.totp.key-file", KEY_FILE.toString())); properties.putAll(overrides);
		return new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(properties).run();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-admin-recovery-test-", ".key"); byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
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
