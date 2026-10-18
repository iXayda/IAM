package com.ixayda.iam.service;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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
import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.credential.TotpSecrets;
import com.ixayda.iam.model.IdentityTotpRecovery;
import com.ixayda.iam.model.PasswordAuthenticationContext;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.session.MapSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityTotpRecoveriesIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "Nine silver lanterns beyond the mountain";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:setup", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final List<String> OLD_TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit",
			"iam_user_totp", "iam_totp_authentication_limit", "iam_mfa_recovery_code", "iam_mfa_recovery_limit");
	private static final List<String> TABLES = Stream.concat(OLD_TABLES.stream(), Stream.of("iam_totp_recovery")).toList();

	@Autowired private IdentityTotpRecoveries recovery;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityAuthentications authentications;
	@Autowired private IdentityBrowserSessions sessions;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityPasswordRecoveries passwordRecoveries;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private TotpSecrets secrets;
	@MockitoSpyBean private TotpCodes codes;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("iam.totp.key-file", KEY_FILE::toString);
	}

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_totp_recovery", "iam_mfa_recovery_code", "iam_mfa_recovery_limit", "iam_user_totp", "iam_totp_authentication_limit",
				"iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit", "iam_security_audit",
				"iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void beginConsumesBothCredentialsButPreservesTheOldFactorSessionsAndPassword() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		addSession(user.id());
		var before = factorRow(user.id());
		var password = passwordRow(user.id());
		var result = begin(set);
		assertThat(result.userId()).isEqualTo(user.id());
		assertThat(result.enrollment().factorId()).isNotEqualTo(factor.factorId());
		assertThat(result.enrollment().expiresAt()).isAfter(Instant.now());
		assertThat(result.enrollment().provisioningUri()).contains("issuer=IAM", result.enrollment().secret());
		assertThat(result.toString()).doesNotContain(result.token(), result.enrollment().secret(), result.enrollment().provisioningUri());
		assertThat(snapshot(this.jdbc, TABLES).toString()).doesNotContain(result.token(), result.enrollment().secret(), PASSWORD);
		assertThat(factorRow(user.id())).isEqualTo(before);
		assertThat(passwordRow(user.id())).isEqualTo(password);
		assertThat(count("iam_browser_session")).isEqualTo(1);
		assertThat(codeRows().stream().filter(row -> row.get("consumed_at") != null)).hasSize(1);
		assertThat(this.recovery.begin(user.id(), PASSWORD, set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(events("totp_recovery_started")).hasSize(1);
		assertThat(events("browser_sessions_revoked")).isEmpty();
	}

	@Test
	void completionAtomicallyReplacesFactorCodesAndVersionAndRejectsStaleLoginEvidence() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var oldSet = issue(factor);
		var password = passwordRow(user.id());
		var authentication = this.authentications.authenticate(user.username(), PASSWORD, passwordContext()).orElseThrow();
		addSession(user.id());
		var other = activeUser("bobby");
		addSession(other.id());
		var pending = begin(oldSet);
		String code = referenceTotp(pending.enrollment(), step());
		var context = totpContext();
		var replacement = this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), code, context).orElseThrow();
		assertThat(replacement.codes()).hasSize(10).doesNotHaveDuplicates().doesNotContainAnyElementsOf(oldSet.codes());
		assertThat(replacement.factorId()).isEqualTo(pending.enrollment().factorId());
		assertThat(replacement.generationId()).isNotEqualTo(oldSet.generationId());
		assertThat(factorRow(user.id())).containsEntry("factor_id", pending.enrollment().factorId()).containsEntry("status", "active");
		assertThat(passwordRow(user.id())).containsEntry("password_hash", password.get("password_hash")).containsEntry("credential_version", 2L);
		assertThat(count("iam_totp_recovery")).isZero();
		assertThat(count("iam_browser_session")).isEqualTo(1);
		assertThat(this.jdbc.sql("SELECT principal_name FROM iam_browser_session").query(String.class).single()).isEqualTo(other.id().toString());
		assertThat(this.totps.verify(user.id(), code, context)).isEmpty();
		assertThat(this.recoveryCodes.consume(user.id(), oldSet.codes().get(1), recoveryContext())).isEmpty();
		assertThat(this.recoveryCodes.consume(user.id(), replacement.codes().getFirst(), recoveryContext())).isPresent();
		assertThat(this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), code, context)).isEmpty();
		assertThat(events("totp_recovery_completed")).hasSize(1).allSatisfy(row -> {
			assertThat(row.get("actor")).isEqualTo("user:" + user.id());
			assertThat(row.get("correlation_id")).isEqualTo(context.correlationId());
		});
		assertThat(events("browser_sessions_revoked")).hasSize(1);
		assertThat(this.sessions.isAuthenticationCurrent(user.id(), System.currentTimeMillis(), authentication.credentialVersion())).isFalse();
		var stale = new MapSession();
		stale.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT, new SecurityContextImpl(
				UsernamePasswordAuthenticationToken.authenticated(user.id(), null, List.of())));
		stale.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, authentication.credentialVersion());
		assertThatIllegalStateException().isThrownBy(() -> this.sessions.save(stale,
				() -> { throw new AssertionError("Stale login must not reach persistence"); }, () -> null, java.util.Set::of));
	}

	@Test
	void completionConsumesTheHighestMatchingStepAndRejectsAdjacentCollisionReplays() {
		var user = activeUser("alice");
		var pending = begin(issue(activeFactor(user.id())));
		// Independent RFC-secret fixture: steps 910737 and 910738 both produce 911617.
		long step = 910737;
		Instant now = Instant.ofEpochSecond(step * 30);
		byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
		var enrollment = new IdentityTotpEnrollment(user.id(), pending.enrollment().factorId(),
				Base32.toBase32String(secret), "unused", now.plusSeconds(600));
		String code = referenceTotp(enrollment, step);
		assertThat(code).isEqualTo("911617").isEqualTo(referenceTotp(enrollment, step + 1));
		this.jdbc.sql("""
				UPDATE iam_totp_recovery SET secret_ciphertext = :secret, issued_at = :issuedAt, expires_at = :expiresAt
				WHERE user_id = :id AND recovery_id = :recoveryId
				""").param("secret", this.secrets.encrypt(user.id(), enrollment.factorId(), secret))
				.param("issuedAt", OffsetDateTime.ofInstant(now, ZoneOffset.UTC))
				.param("expiresAt", OffsetDateTime.ofInstant(enrollment.expiresAt(), ZoneOffset.UTC))
				.param("id", user.id()).param("recoveryId", pending.recoveryId()).update();
		String schema = "recovery_clock_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			this.jdbc.sql("CREATE TABLE " + schema + ".instant (now TIMESTAMPTZ NOT NULL)").update();
			this.jdbc.sql("INSERT INTO " + schema + ".instant VALUES (:now)")
					.param("now", OffsetDateTime.ofInstant(now, ZoneOffset.UTC)).update();
			// Only this context resolves the controlled clock before pg_catalog; SQL and OTP computation stay real.
			this.jdbc.sql("CREATE FUNCTION " + schema + ".clock_timestamp() RETURNS TIMESTAMPTZ LANGUAGE SQL VOLATILE AS 'SELECT now FROM " + schema + ".instant'").update();
			try (var controlled = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
					"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
					"spring.datasource.password", this.postgres.getPassword(), "spring.flyway.enabled", false,
					"spring.datasource.hikari.connection-init-sql", "SET search_path TO " + schema + ", public, pg_catalog"))
					.run("--iam.totp.key-file=" + KEY_FILE)) {
				assertThat(controlled.getBean(JdbcClient.class).sql("SELECT clock_timestamp()")
						.query((row, index) -> row.getObject(1, OffsetDateTime.class).toInstant()).single()).isEqualTo(now);
				var recoveries = controlled.getBean(IdentityTotpRecoveries.class);
				var factors = controlled.getBean(IdentityTotps.class);
				assertThat(recoveries.complete(user.id(), pending.recoveryId(), pending.token(), code, totpContext())).isPresent();
				assertThat(factorRow(user.id())).containsEntry("factor_id", enrollment.factorId()).containsEntry("last_used_step", step + 1);
				assertThat(factors.verify(user.id(), code, totpContext())).isEmpty();
				this.jdbc.sql("UPDATE " + schema + ".instant SET now = now + INTERVAL '30 seconds'").update();
				assertThat(factors.verify(user.id(), referenceTotp(enrollment, step + 1), totpContext())).isEmpty();
				assertThat(factors.verify(user.id(), referenceTotp(enrollment, step + 2), totpContext())).isPresent();
				assertThat(factorRow(user.id())).containsEntry("last_used_step", step + 2);
				assertThat(events("totp_recovery_completed")).hasSize(1);
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "wrong-password", "wrong-code", "other-user", "unknown", "disabled", "no-password", "pending-factor" })
	void beginRequiresBothCurrentCredentialsAndTheActiveOwner(String state) {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		UUID id = user.id();
		String password = PASSWORD;
		String code = set.codes().getFirst();
		switch (state) {
			case "wrong-password" -> password = NEW_PASSWORD;
			case "wrong-code" -> code = "bad";
			case "other-user" -> { var other = activeUser("bobby"); activeFactor(other.id()); id = other.id(); }
			case "unknown" -> id = UUID.randomUUID();
			case "disabled" -> this.states.disable(id, SYSTEM);
			case "no-password" -> this.jdbc.sql("DELETE FROM iam_password WHERE user_id = :id").param("id", id).update();
			case "pending-factor" -> this.jdbc.sql("UPDATE iam_user_totp SET status = 'pending', activated_at = NULL, last_used_step = NULL WHERE user_id = :id").param("id", id).update();
			default -> throw new AssertionError(state);
		}
		assertThat(this.recovery.begin(id, password, code, recoveryContext())).isEmpty();
		assertThat(count("iam_totp_recovery")).isZero();
		assertThat(codeRows()).allSatisfy(row -> assertThat(row.get("consumed_at")).isNull());
		assertThat(events("totp_recovery_started")).isEmpty();
	}

	@ParameterizedTest
	@MethodSource("invalidTokens")
	void malformedOrIncorrectProofIsMeteredAndDoesNotMutateTheFactor(String token) {
		var user = activeUser("alice");
		var pending = begin(issue(activeFactor(user.id())));
		var before = factorRow(user.id());
		assertThat(this.recovery.complete(user.id(), pending.recoveryId(), token,
				referenceTotp(pending.enrollment(), step()), totpContext())).isEmpty();
		assertThat(factorRow(user.id())).isEqualTo(before);
		assertThat(count("iam_totp_recovery")).isEqualTo(1);
		assertThat(failures("account")).containsExactly(1);
		assertThat(events("totp_recovery_failed")).hasSize(1).allSatisfy(row -> assertThat(row.get("actor")).isEqualTo("anonymous"));
	}

	static Stream<String> invalidTokens() { return Stream.of(null, "", "wrong", "A".repeat(43), "A".repeat(42) + "B", "x".repeat(65536)); }

	@ParameterizedTest
	@ValueSource(strings = { "expired", "recovery-id", "other-user", "unknown", "old-factor", "regenerated-codes", "password-recovery", "disable-enable", "wrong-totp" })
	void completionRejectsExpiredOrStaleBindingsAndWrongNewFactorCodes(String state) {
		var user = activeUser("alice");
		var oldFactor = activeFactor(user.id());
		var pending = begin(issue(oldFactor));
		UUID id = user.id();
		UUID recoveryId = pending.recoveryId();
		String code = referenceTotp(pending.enrollment(), step());
		switch (state) {
			case "expired" -> expire(user.id());
			case "recovery-id" -> recoveryId = UUID.randomUUID();
			case "other-user" -> { var other = activeUser("bobby"); activeFactor(other.id()); id = other.id(); }
			case "unknown" -> id = UUID.randomUUID();
			case "old-factor" -> { this.jdbc.sql("DELETE FROM iam_user_totp WHERE user_id = :id").param("id", user.id()).update(); activeFactor(user.id()); }
			case "regenerated-codes" -> issue(oldFactor);
			case "password-recovery" -> {
				var proof = this.passwordRecoveries.issue(user.id(), SYSTEM);
				this.passwordRecoveries.complete(user.id(), proof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID());
			}
			case "disable-enable" -> { this.states.disable(id, SYSTEM); this.states.enable(id, SYSTEM); }
			case "wrong-totp" -> code = "bad";
			default -> throw new AssertionError(state);
		}
		var before = factorRow(user.id());
		assertThat(this.recovery.complete(id, recoveryId, pending.token(), code, totpContext())).isEmpty();
		assertThat(factorRow(user.id())).isEqualTo(before);
		assertThat(events("totp_recovery_completed")).isEmpty();
	}

	@Test
	void replacingPendingRecoveryInvalidatesItsTokenAndRequiresAnotherUnusedCode() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var first = begin(set);
		var second = this.recovery.begin(user.id(), PASSWORD, set.codes().get(1), recoveryContext()).orElseThrow();
		assertThat(second.recoveryId()).isNotEqualTo(first.recoveryId());
		assertThat(this.recovery.complete(user.id(), first.recoveryId(), first.token(), referenceTotp(first.enrollment(), step()), totpContext())).isEmpty();
		assertThat(this.recovery.complete(user.id(), second.recoveryId(), second.token(), referenceTotp(second.enrollment(), step()), totpContext())).isPresent();
		assertThat(events("totp_recovery_completed")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "begin", "complete" })
	void concurrentUsePublishesOnlyOneRecoveryOrReplacementCodeSet(String operation) throws Exception {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var pending = operation.equals("complete") ? begin(set) : null;
		String code = pending == null ? null : referenceTotp(pending.enrollment(), step());
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = Stream.of(1, 2).map(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				return operation.equals("begin")
						? this.recovery.begin(user.id(), PASSWORD, set.codes().getFirst(), recoveryContext("192.0.2." + index)).isPresent()
						: this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), code, totpContext()).isPresent();
			})).toList();
			start.countDown();
			int successes = 0;
			for (var task : tasks) { if (task.get(15, TimeUnit.SECONDS)) { successes++; } }
			assertThat(successes).isEqualTo(1);
		}
		assertThat(events(operation.equals("begin") ? "totp_recovery_started" : "totp_recovery_completed")).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "password_authenticated", "mfa_recovery_code_consumed", "totp_recovery_started",
			"browser_sessions_revoked", "mfa_recovery_codes_generated", "totp_recovery_completed", "totp_recovery_failed", "totp_recovery_throttled" })
	void requiredAuditFailureRollsBackEveryCredentialBudgetFactorAndSessionChange(String action) {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		addSession(user.id());
		boolean starting = List.of("password_authenticated", "mfa_recovery_code_consumed", "totp_recovery_started").contains(action);
		var pending = starting ? null : begin(set);
		if (action.equals("totp_recovery_throttled")) {
			for (int index = 0; index < 5; index++) { this.recovery.complete(user.id(), pending.recoveryId(), "bad", "bad", totpContext()); }
		}
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT totp_recovery_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try {
			assertThatThrownBy(() -> {
				if (starting) { begin(set); }
				else { this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), action.equals("totp_recovery_failed") ? "bad" : referenceTotp(pending.enrollment(), step()), totpContext()); }
			}).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT totp_recovery_test_reject").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "begin", "complete" })
	void deferredCommitFailureDoesNotDeliverSecretsOrCommitPartialRecovery(String operation) {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var pending = operation.equals("complete") ? begin(set) : null;
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION totp_recovery_test_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test commit failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE CONSTRAINT TRIGGER totp_recovery_test_commit AFTER INSERT OR DELETE ON iam_totp_recovery DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION totp_recovery_test_commit()").update();
			assertThatThrownBy(() -> {
				if (pending == null) { begin(set); }
				else { this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext()); }
			}).isInstanceOf(TransactionSystemException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION totp_recovery_test_commit() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "grant-insert", "grant-delete", "factor-delete", "factor-insert", "version", "code-insert", "session-delete", "budget", "budget-success", "password-budget", "password-budget-success" })
	void suppressedMandatoryWritesCannotPublishSuccessfulRecovery(String fault) {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		addSession(user.id());
		var pending = fault.equals("grant-insert") || fault.startsWith("password-budget") ? null : begin(set);
		if (fault.equals("password-budget-success")) { this.authentications.authenticate(user.username(), "bad", passwordContext()); }
		if (fault.equals("budget-success")) { this.recovery.complete(user.id(), pending.recoveryId(), "bad", "bad", totpContext()); }
		var before = snapshot(this.jdbc, TABLES);
		String table = switch (fault) {
			case "grant-insert", "grant-delete" -> "iam_totp_recovery";
			case "factor-delete", "factor-insert" -> "iam_user_totp";
			case "version" -> "iam_password";
			case "code-insert" -> "iam_mfa_recovery_code";
			case "session-delete" -> "iam_browser_session";
			case "budget", "budget-success" -> "iam_totp_authentication_limit";
			case "password-budget", "password-budget-success" -> "iam_password_authentication_limit";
			default -> throw new AssertionError(fault);
		};
		String mutation = fault.endsWith("delete") ? "DELETE" : fault.equals("version") || fault.contains("budget") ? "UPDATE" : "INSERT";
		// UPDATE returns OLD so an affected-row count alone cannot detect a silently ignored write.
		this.jdbc.sql("CREATE FUNCTION totp_recovery_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN " + (mutation.equals("UPDATE") ? "OLD" : "NULL") + "; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER totp_recovery_test_suppress BEFORE " + mutation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION totp_recovery_test_suppress()").update();
			assertThatThrownBy(() -> {
				if (pending == null) { this.recovery.begin(user.id(), fault.equals("password-budget") ? "bad" : PASSWORD, set.codes().getFirst(), recoveryContext()); }
				else { this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), fault.equals("budget") ? "bad" : referenceTotp(pending.enrollment(), step()), totpContext()); }
			}).isInstanceOf(RuntimeException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION totp_recovery_test_suppress() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void corruptPendingSecretIsASystemFailureAndPreservesAllState() {
		var user = activeUser("alice");
		var pending = begin(issue(activeFactor(user.id())));
		this.jdbc.sql("UPDATE iam_totp_recovery SET secret_ciphertext = 'v1.' || repeat('A',64)").update();
		var before = snapshot(this.jdbc, TABLES);
		assertThatIllegalStateException().isThrownBy(() -> this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), "123456", totpContext()));
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void recoverySharesExistingPasswordRecoveryCodeAndTotpBudgets() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		for (int index = 0; index < 10; index++) { this.authentications.authenticate(user.username(), "bad", passwordContext()); }
		assertThat(this.recovery.begin(user.id(), PASSWORD, set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(events("password_auth_throttled")).hasSize(1);
		this.jdbc.sql("DELETE FROM iam_password_authentication_limit").update();
		// The password-throttled recovery attempt above already used one recovery failure.
		for (int index = 0; index < 4; index++) { this.recoveryCodes.consume(user.id(), "bad", recoveryContext()); }
		assertThat(this.recovery.begin(user.id(), PASSWORD, set.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(events("mfa_recovery_code_throttled")).hasSize(1);
		this.jdbc.sql("DELETE FROM iam_mfa_recovery_limit").update();
		var pending = begin(set);
		for (int index = 0; index < 5; index++) { this.totps.verify(user.id(), "bad", totpContext()); }
		assertThat(this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isEmpty();
		assertThat(events("totp_recovery_throttled")).hasSize(1);
		this.jdbc.sql("UPDATE iam_totp_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
		assertThat(this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "expire", "disable", "regenerate", "password" })
	void waitingForTheUserLockRechecksRecoveryTimeAndBindings(String change) throws Exception {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var pending = begin(set);
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.lockById(user.id());
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				switch (change) {
					case "expire" -> expire(user.id());
					case "disable" -> this.states.disable(user.id(), SYSTEM);
					case "regenerate" -> this.jdbc.sql("DELETE FROM iam_mfa_recovery_code WHERE user_id = :id").param("id", user.id()).update();
					case "password" -> this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id").param("id", user.id()).update();
					default -> throw new AssertionError(change);
				}
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
				var attempt = executor.submit(() -> this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext()));
				awaitUserLockWait();
				release.countDown();
				blocker.get(10, TimeUnit.SECONDS);
				assertThat(attempt.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
		assertThat(events("totp_recovery_completed")).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "expiry", "window" })
	void consumingWriteRechecksDeadlineAndWindowAfterVerification(String boundary) {
		var user = activeUser("alice");
		var pending = begin(issue(activeFactor(user.id())));
		doAnswer(call -> {
			if (boundary.equals("expiry")) { expire(user.id()); }
			return java.util.OptionalLong.of(boundary.equals("window") ? step() - 2 : step());
		}).when(this.codes).match(any(byte[].class), anyString(), any(Instant.class), anyLong());
		assertThat(this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), "123456", totpContext())).isEmpty();
		assertThat(events("totp_recovery_completed")).isEmpty();
		assertThat(count("iam_totp_recovery")).isEqualTo(1);
	}

	@Test
	void rejectsAmbientTransactionsMissingContextsAndUntrustedDecisionSubstitution() {
		var user = activeUser("alice");
		var before = snapshot(this.jdbc, TABLES);
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.begin(user.id(), PASSWORD, "bad", recoveryContext()));
			assertThatIllegalStateException().isThrownBy(() -> this.recovery.complete(user.id(), UUID.randomUUID(), "bad", "bad", totpContext()));
		});
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.begin(user.id(), PASSWORD, "bad", null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.complete(user.id(), null, "bad", "bad", totpContext()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.complete(user.id(), UUID.randomUUID(), "bad", "bad", null));
		assertThatThrownBy(() -> this.authentications.authenticateInTransaction(user.username(), PASSWORD, passwordContext()))
				.isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.recoveryCodes.consumeInTransaction(user.id(), "bad", recoveryContext()))
				.isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.recoveryCodes.issueForVerifiedFactor(user.id(), UUID.randomUUID(), SYSTEM))
				.isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void restartKeepsPendingGrantAndMissingKeyFailsBeforeConsumingCredentials() {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		var pending = begin(set);
		try (var unavailable = restart("")) {
			var service = unavailable.getBean(IdentityTotpRecoveries.class);
			var before = snapshot(this.jdbc, TABLES);
			assertThatIllegalStateException().isThrownBy(() -> service.begin(user.id(), PASSWORD, set.codes().get(1), recoveryContext()));
			assertThatIllegalStateException().isThrownBy(() -> service.complete(user.id(), pending.recoveryId(), pending.token(), "123456", totpContext()));
			assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
		}
		try (var restarted = restart(KEY_FILE.toString())) {
			assertThat(restarted.getBean(IdentityTotpRecoveries.class).complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isPresent();
		}
	}

	@Test
	void cleanupPreservesActiveFactorsCodeReplayAndUnexpiredPendingGrants() {
		var alice = activeUser("alice");
		var expired = begin(issue(activeFactor(alice.id())));
		var bob = activeUser("bobby");
		var current = begin(issue(activeFactor(bob.id())));
		expire(alice.id());
		var before = snapshot(this.jdbc, List.of("iam_user_totp", "iam_mfa_recovery_code"));
		this.recovery.cleanUpExpiredRecoveries();
		assertThat(count("iam_totp_recovery")).isEqualTo(1);
		assertThat(snapshot(this.jdbc, List.of("iam_user_totp", "iam_mfa_recovery_code"))).isEqualTo(before);
		assertThat(this.recovery.complete(alice.id(), expired.recoveryId(), expired.token(), referenceTotp(expired.enrollment(), step()), totpContext())).isEmpty();
		assertThat(this.recovery.complete(bob.id(), current.recoveryId(), current.token(), referenceTotp(current.enrollment(), step()), totpContext())).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "token_digest = 'plaintext'", "expires_at = issued_at + INTERVAL '11 minutes'", "issued_at = '-infinity'",
			"credential_version = 0", "new_factor_id = old_factor_id", "old_factor_id = gen_random_uuid()", "secret_ciphertext = 'plaintext'" })
	void databaseRejectsInvalidRecoveryState(String assignment) {
		var user = activeUser("alice");
		begin(issue(activeFactor(user.id())));
		var before = snapshot(this.jdbc, TABLES);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_totp_recovery SET " + assignment).update()).isInstanceOf(DataAccessException.class);
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void upgradingV13PreservesExistingBusinessDataAndDoesNotInventRecoveryGrants() throws Exception {
		var user = activeUser("alice");
		var set = issue(activeFactor(user.id()));
		this.recoveryCodes.consume(user.id(), set.codes().getFirst(), recoveryContext());
		addSession(user.id());
		String schema = "totp_recovery_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "13").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : OLD_TABLES) { previous.sql("INSERT INTO " + table + " SELECT * FROM public." + table).update(); }
				var before = snapshot(previous, OLD_TABLES);
				flyway(schema, "14").migrate();
				assertThat(snapshot(previous, OLD_TABLES)).isEqualTo(before);
				assertThat(previous.sql("SELECT count(*) FROM iam_totp_recovery").query(Long.class).single()).isZero();
				assertThat(flyway(schema, "14").migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	@Test
	void ordinaryFactorAndCodeWorkflowsCanRunAlongsideRecoveryWithoutLockInversion() throws Exception {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var set = issue(factor);
		var pending = begin(set);
		String oldCode = freshTotp(factor);
		String newCode = referenceTotp(pending.enrollment(), step());
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(4)) {
			var operations = List.<Runnable>of(
					() -> this.recovery.begin(user.id(), PASSWORD, set.codes().get(1), recoveryContext()),
					() -> this.recoveryCodes.issue(user.id(), oldCode, totpContext()),
					() -> this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), newCode, totpContext()),
					() -> this.authentications.authenticate(user.username(), PASSWORD, passwordContext()));
			var tasks = operations.stream().map(operation -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				operation.run();
				return true;
			})).toList();
			start.countDown();
			for (var task : tasks) { assertThat(task.get(15, TimeUnit.SECONDS)).isTrue(); }
		}
		assertThat(events("totp_recovery_completed")).hasSizeLessThanOrEqualTo(1);
		assertThat(count("iam_user_totp")).isEqualTo(1);
		assertThat(codeRows()).hasSize(10);
	}

	@Test
	void completionSourceBudgetSpansUsersAndDoesNotCreateMoreAccountBucketsWhileBlocked() {
		var user = activeUser("alice");
		var pending = begin(issue(activeFactor(user.id())));
		for (int index = 0; index < 30; index++) {
			assertThat(this.recovery.complete(UUID.randomUUID(), UUID.randomUUID(), "bad", "bad", totpContext())).isEmpty();
		}
		assertThat(failures("source")).containsExactly(30);
		int accounts = failures("account").size();
		assertThat(this.recovery.complete(UUID.randomUUID(), UUID.randomUUID(), "bad", "bad", totpContext())).isEmpty();
		var otherEntry = new TotpAuthenticationContext("another:entry", totpContext().clientAddress(), UUID.randomUUID());
		assertThat(this.recovery.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), otherEntry)).isEmpty();
		assertThat(failures("account")).hasSize(accounts);
		assertThat(events("totp_recovery_throttled")).hasSize(2).allSatisfy(row -> assertThat(row.get("target_user_id")).isNull());
		assertThat(count("iam_totp_recovery")).isEqualTo(1);
	}

	@Test
	void blockedPasswordSourcesCannotCreateUnboundedRecoveryAccountBudgets() {
		for (int index = 0; index < 50; index++) { this.authentications.authenticate("unknown-" + index, "bad", passwordContext()); }
		for (int index = 0; index < 30; index++) {
			assertThat(this.recovery.begin(UUID.randomUUID(), "bad", "bad", recoveryContext())).isEmpty();
		}
		assertThat(this.jdbc.sql("SELECT failures FROM iam_mfa_recovery_limit WHERE dimension = 'source'").query(Integer.class).single()).isEqualTo(30);
		long before = this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_limit WHERE dimension = 'account'").query(Long.class).single();
		assertThat(this.recovery.begin(UUID.randomUUID(), "bad", "bad", recoveryContext())).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_mfa_recovery_limit WHERE dimension = 'account'").query(Long.class).single()).isEqualTo(before);
		assertThat(events("mfa_recovery_code_throttled")).hasSize(1);
	}

	@Test
	void recoveryFailureBudgetsAndPendingProofSurviveRestart() {
		var user = activeUser("alice");
		var pending = begin(issue(activeFactor(user.id())));
		for (int index = 0; index < 5; index++) { this.recovery.complete(user.id(), pending.recoveryId(), "bad", "bad", totpContext()); }
		try (var restarted = restart(KEY_FILE.toString())) {
			var service = restarted.getBean(IdentityTotpRecoveries.class);
			assertThat(service.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isEmpty();
			assertThat(events("totp_recovery_throttled")).hasSize(1);
			this.jdbc.sql("UPDATE iam_totp_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
			assertThat(service.complete(user.id(), pending.recoveryId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isPresent();
		}
	}

	@Test
	void cleanupSkipsLockedPendingGrantsWithoutWaitingOrDeletingFactors() throws Exception {
		var alice = activeUser("alice");
		begin(issue(activeFactor(alice.id())));
		var bob = activeUser("bobby");
		begin(issue(activeFactor(bob.id())));
		expire(alice.id());
		expire(bob.id());
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SELECT user_id FROM iam_totp_recovery WHERE user_id = :id FOR UPDATE").param("id", alice.id()).query(UUID.class).single();
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
				executor.submit(this.recovery::cleanUpExpiredRecoveries).get(5, TimeUnit.SECONDS);
				assertThat(this.jdbc.sql("SELECT user_id FROM iam_totp_recovery").query(UUID.class).list()).containsExactly(alice.id());
				assertThat(count("iam_user_totp")).isEqualTo(2);
			}
			finally { release.countDown(); }
			blocker.get(10, TimeUnit.SECONDS);
		}
		this.recovery.cleanUpExpiredRecoveries();
		assertThat(count("iam_totp_recovery")).isZero();
		assertThat(count("iam_mfa_recovery_code")).isEqualTo(20);
	}

	@Test
	void cleanupIsBoundedToOneThousandExpiredGrantsPerCall() {
		var user = activeUser("alice");
		begin(issue(activeFactor(user.id())));
		expire(user.id());
		// These rows exercise cleanup only; copying opaque ciphertext does not create usable factors.
		this.jdbc.sql("INSERT INTO iam_user (id, username, display_name, status) SELECT gen_random_uuid(), 'cleanup-' || n, 'Cleanup', 'active' FROM generate_series(1, 1000) n").update();
		this.jdbc.sql("""
				INSERT INTO iam_user_totp (user_id, factor_id, secret_ciphertext, key_id, enrollment_credential_version, status, issued_at, expires_at, activated_at, last_used_step)
				SELECT u.id, gen_random_uuid(), t.secret_ciphertext, t.key_id, t.enrollment_credential_version,
				    t.status, t.issued_at, t.expires_at, t.activated_at, t.last_used_step
				FROM iam_user u CROSS JOIN iam_user_totp t WHERE u.username LIKE 'cleanup-%' AND t.user_id = :id
				""").param("id", user.id()).update();
		this.jdbc.sql("""
				INSERT INTO iam_totp_recovery (user_id, recovery_id, old_factor_id, new_factor_id, recovery_generation_id,
				    credential_version, token_digest, secret_ciphertext, key_id, issued_at, expires_at)
				SELECT t.user_id, gen_random_uuid(), t.factor_id, gen_random_uuid(), gen_random_uuid(),
				    r.credential_version, r.token_digest, r.secret_ciphertext, r.key_id, r.issued_at, r.expires_at
				FROM iam_user_totp t CROSS JOIN iam_totp_recovery r WHERE r.user_id = :id AND t.user_id <> :id
				""").param("id", user.id()).update();
		assertThat(count("iam_totp_recovery")).isEqualTo(1001);
		this.recovery.cleanUpExpiredRecoveries();
		assertThat(count("iam_totp_recovery")).isEqualTo(1);
		this.recovery.cleanUpExpiredRecoveries();
		assertThat(count("iam_totp_recovery")).isZero();
		assertThat(count("iam_user_totp")).isEqualTo(1001);
		assertThat(count("iam_mfa_recovery_code")).isEqualTo(10);
	}

	private org.springframework.context.ConfigurableApplicationContext restart(String key) {
		return new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword())).run("--iam.totp.key-file=" + key);
	}

	private IdentityTotpRecovery begin(MfaRecoveryCodeSet set) {
		return this.recovery.begin(set.userId(), PASSWORD, set.codes().getFirst(), recoveryContext()).orElseThrow();
	}

	private void expire(UUID userId) {
		this.jdbc.sql("UPDATE iam_totp_recovery SET issued_at = t.now - INTERVAL '11 minutes', expires_at = t.now - INTERVAL '1 minute' FROM (SELECT clock_timestamp() AS now) t WHERE user_id = :id")
				.param("id", userId).update();
	}

	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }

	private Map<String, Object> passwordRow(UUID userId) {
		return this.jdbc.sql("SELECT * FROM iam_password WHERE user_id = :id").param("id", userId).query().singleRow();
	}

	private void addSession(UUID userId) {
		String id = UUID.randomUUID().toString();
		long now = System.currentTimeMillis();
		this.jdbc.sql("INSERT INTO iam_browser_session VALUES (:id, :id, :now, :now, 1800, :expiry, :principal)")
				.param("id", id).param("now", now).param("expiry", now + 1800000).param("principal", userId.toString()).update();
		this.jdbc.sql("INSERT INTO iam_browser_session_attributes VALUES (:id, 'test-marker', :bytes)")
				.param("id", id).param("bytes", new byte[] { 1 }).update();
	}

	private static PasswordAuthenticationContext passwordContext() {
		var context = recoveryContext();
		return new PasswordAuthenticationContext(context.source(), context.clientAddress(), context.correlationId());
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
		return this.recoveryCodes.issue(factor.userId(), freshTotp(factor), totpContext()).orElseThrow();
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
		return this.jdbc.sql("SELECT failures FROM iam_totp_authentication_limit WHERE dimension = :dimension ORDER BY subject_key")
				.param("dimension", dimension).query(Integer.class).list();
	}

	private static TotpAuthenticationContext totpContext() {
		var recovery = recoveryContext();
		return new TotpAuthenticationContext("internal:totp-recovery", recovery.clientAddress(), UUID.randomUUID());
	}

	private static MfaRecoveryCodeContext recoveryContext() { return recoveryContext("192.0.2.100"); }

	private static MfaRecoveryCodeContext recoveryContext(String address) {
		try { return new MfaRecoveryCodeContext("internal:totp-recovery", InetAddress.getByName(address), UUID.randomUUID()); }
		catch (Exception ex) { throw new IllegalStateException(ex); }
	}

	private static Path keyFile() {
		try {
			byte[] key = new byte[32];
			new SecureRandom().nextBytes(key);
			Path file = Files.createTempFile("iam-totp-recovery-test-", ".key");
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
		throw new AssertionError("TOTP recovery did not reach the user lock");
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
