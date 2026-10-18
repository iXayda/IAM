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
import com.ixayda.iam.model.IdentityTotpReplacement;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityTotpReplacementsIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:setup", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final List<String> TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit",
			"iam_user_totp", "iam_totp_authentication_limit", "iam_mfa_recovery_code", "iam_mfa_recovery_limit", "iam_totp_recovery", "iam_totp_replacement");

	@Autowired private IdentityTotpReplacements replacements;
	@Autowired private IdentityTotpRecoveries recoveries;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityAuthentications authentications;
	@Autowired private IdentityBrowserSessions sessions;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private TotpSecrets secrets;
	@MockitoSpyBean private TotpCodes codes;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_totp_replacement", "iam_totp_recovery", "iam_mfa_recovery_code", "iam_mfa_recovery_limit",
				"iam_user_totp", "iam_totp_authentication_limit", "iam_browser_session_attributes", "iam_browser_session",
				"iam_password_authentication_limit", "iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void beginVerifiesBothCredentialsAndRetainsTheOldFactorCodesSessionsAndPassword() {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		var oldCodes = issue(factor);
		addSession(user.id());
		var password = passwordRow(user.id());
		var storedCodes = codeRows();
		var pending = begin(factor);
		assertThat(pending.enrollment().factorId()).isNotEqualTo(factor.factorId());
		assertThat(pending.enrollment().expiresAt()).isAfter(Instant.now().plusSeconds(590)).isBefore(Instant.now().plusSeconds(601));
		assertThat(factorRow(user.id())).containsEntry("factor_id", factor.factorId()).containsEntry("status", "active");
		assertThat(codeRows()).isEqualTo(storedCodes).hasSize(10);
		assertThat(passwordRow(user.id())).isEqualTo(password);
		assertThat(count("iam_browser_session")).isEqualTo(1);
		var stored = this.jdbc.sql("SELECT * FROM iam_totp_replacement").query().singleRow();
		assertThat(stored.values()).doesNotContain(pending.token(), pending.enrollment().secret(), pending.enrollment().provisioningUri());
		assertThat(pending.toString()).doesNotContain(pending.token(), pending.enrollment().secret());
		assertThat(oldCodes.codes()).noneMatch(value -> stored.values().contains(value));
		assertThat(events("totp_replacement_started")).hasSize(1);
		assertThat(events("totp_authenticated")).hasSize(2);
		assertThat(this.replacements.begin(user.id(), PASSWORD, referenceTotp(factor, step()), totpContext())).isEmpty();
	}

	@Test
	void confirmationReplacesOnlyTheOwnersFactorCodesAndSessionsAndInvalidatesOldAuthentication() {
		var user = activeUser("alice");
		var other = activeUser("bob");
		var factor = activeFactor(user.id());
		var oldCodes = issue(factor);
		var password = passwordRow(user.id());
		var login = this.authentications.authenticate(user.username(), PASSWORD, passwordContext()).orElseThrow();
		addSession(user.id()); addSession(other.id());
		var pending = begin(factor);
		String code = referenceTotp(pending.enrollment(), step());
		var result = this.replacements.complete(user.id(), pending.replacementId(), pending.token(), code, totpContext()).orElseThrow();
		assertThat(result.factorId()).isEqualTo(pending.enrollment().factorId());
		assertThat(result.codes()).hasSize(10).doesNotContainAnyElementsOf(oldCodes.codes());
		assertThat(factorRow(user.id())).containsEntry("factor_id", result.factorId()).containsEntry("status", "active");
		assertThat(passwordRow(user.id())).containsEntry("password_hash", password.get("password_hash"))
				.containsEntry("credential_version", login.credentialVersion() + 1);
		assertThat(codeRows()).hasSize(10).allSatisfy(row -> assertThat(row).containsEntry("factor_id", result.factorId()));
		assertThat(count("iam_totp_replacement")).isZero();
		assertThat(this.jdbc.sql("SELECT principal_name FROM iam_browser_session").query(String.class).list()).containsExactly(other.id().toString());
		assertThat(this.sessions.isAuthenticationCurrent(user.id(), System.currentTimeMillis(), login.credentialVersion())).isFalse();
		assertThat(this.totps.verify(user.id(), code, totpContext())).isEmpty();
		assertThat(this.replacements.complete(user.id(), pending.replacementId(), pending.token(), code, totpContext())).isEmpty();
		assertThat(this.recoveryCodes.consume(user.id(), oldCodes.codes().getFirst(), recoveryContext())).isEmpty();
		assertThat(events("totp_replacement_completed")).hasSize(1);
		assertThat(events("browser_sessions_revoked")).hasSize(1);
	}

	@Test
	void completionConsumesTheHighestMatchingStepAndRejectsAdjacentCollisionReplays() {
		var user = activeUser("alice");
		var pending = begin(activeFactor(user.id()));
		// Independent RFC-secret fixture: steps 910737 and 910738 both produce 911617.
		long step = 910737;
		Instant now = Instant.ofEpochSecond(step * 30);
		byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
		var enrollment = new IdentityTotpEnrollment(user.id(), pending.enrollment().factorId(),
				Base32.toBase32String(secret), "unused", now.plusSeconds(600));
		String code = referenceTotp(enrollment, step);
		assertThat(code).isEqualTo("911617").isEqualTo(referenceTotp(enrollment, step + 1));
		this.jdbc.sql("""
				UPDATE iam_totp_replacement SET secret_ciphertext = :secret, issued_at = :issuedAt, expires_at = :expiresAt
				WHERE user_id = :id AND replacement_id = :replacementId
				""").param("secret", this.secrets.encrypt(user.id(), enrollment.factorId(), secret))
				.param("issuedAt", OffsetDateTime.ofInstant(now, ZoneOffset.UTC))
				.param("expiresAt", OffsetDateTime.ofInstant(enrollment.expiresAt(), ZoneOffset.UTC))
				.param("id", user.id()).param("replacementId", pending.replacementId()).update();
		String schema = "replacement_clock_" + UUID.randomUUID().toString().replace("-", "");
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
				var replacements = controlled.getBean(IdentityTotpReplacements.class);
				var factors = controlled.getBean(IdentityTotps.class);
				assertThat(replacements.complete(user.id(), pending.replacementId(), pending.token(), code, totpContext())).isPresent();
				assertThat(factorRow(user.id())).containsEntry("factor_id", enrollment.factorId()).containsEntry("last_used_step", step + 1);
				assertThat(factors.verify(user.id(), code, totpContext())).isEmpty();
				this.jdbc.sql("UPDATE " + schema + ".instant SET now = now + INTERVAL '30 seconds'").update();
				assertThat(factors.verify(user.id(), referenceTotp(enrollment, step + 1), totpContext())).isEmpty();
				assertThat(factors.verify(user.id(), referenceTotp(enrollment, step + 2), totpContext())).isPresent();
				assertThat(factorRow(user.id())).containsEntry("last_used_step", step + 2);
				assertThat(events("totp_replacement_completed")).hasSize(1);
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}


	@ParameterizedTest
	@ValueSource(strings = { "password", "code", "replay", "unknown", "disabled", "no-password", "pending-factor" })
	void beginRejectsMissingOrInvalidCurrentCredentialsAndInactiveOwners(String state) {
		var user = activeUser("alice");
		var factor = activeFactor(user.id());
		if (state.equals("disabled")) { this.states.disable(user.id(), SYSTEM); }
		if (state.equals("no-password")) { this.jdbc.sql("DELETE FROM iam_password").update(); }
		if (state.equals("pending-factor")) {
			this.jdbc.sql("UPDATE iam_user_totp SET status = 'pending', activated_at = NULL, last_used_step = NULL").update();
		}
		String code = referenceTotp(factor, step());
		if (state.equals("replay")) { assertThat(this.totps.verify(user.id(), code, totpContext())).isPresent(); }
		assertThat(this.replacements.begin(state.equals("unknown") ? UUID.randomUUID() : user.id(),
				state.equals("password") ? "wrong" : PASSWORD, state.equals("code") ? "bad" : code, totpContext())).isEmpty();
		assertThat(count("iam_totp_replacement")).isZero();
		assertThat(events("totp_replacement_started")).isEmpty();
	}

	@ParameterizedTest
	@MethodSource("invalidTokens")
	void invalidCompletionProofIsMeteredAndDoesNotReplaceTheFactor(String token) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var pending = begin(factor);
		assertThat(this.replacements.complete(user.id(), pending.replacementId(), token,
				referenceTotp(pending.enrollment(), step()), totpContext())).isEmpty();
		assertThat(factorRow(user.id())).containsEntry("factor_id", factor.factorId());
		assertThat(count("iam_totp_replacement")).isEqualTo(1);
		assertThat(failures("account")).containsExactly(1);
		assertThat(events("totp_replacement_failed")).hasSize(1);
	}

	static Stream<String> invalidTokens() { return Stream.of(null, "", "wrong", "A".repeat(43), "A".repeat(42) + "B", "x".repeat(65536)); }

	@ParameterizedTest
	@ValueSource(strings = { "expired", "version", "disabled", "reactivated", "wrong-code", "wrong-id", "other-user" })
	void completionRechecksOwnerVersionFactorStateDeadlineAndNewCode(String state) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var pending = begin(factor);
		if (state.equals("expired")) { expire(user.id()); }
		if (state.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
		if (state.equals("disabled") || state.equals("reactivated")) { this.states.disable(user.id(), SYSTEM); }
		if (state.equals("reactivated")) { this.states.enable(user.id(), SYSTEM); }
		assertThat(this.replacements.complete(state.equals("other-user") ? activeUser("bob").id() : user.id(),
				state.equals("wrong-id") ? UUID.randomUUID() : pending.replacementId(), pending.token(),
				state.equals("wrong-code") ? "bad" : referenceTotp(pending.enrollment(), step()), totpContext())).isEmpty();
		assertThat(factorRow(user.id())).containsEntry("factor_id", factor.factorId());
		assertThat(events("totp_replacement_completed")).isEmpty();
	}

	@Test
	void aFreshOldFactorCodeReplacesThePendingGrantAndOldProofCannotComplete() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var first = begin(factor);
		var second = this.replacements.begin(user.id(), PASSWORD, referenceTotp(factor, step() + 1), totpContext()).orElseThrow();
		assertThat(this.replacements.complete(user.id(), first.replacementId(), first.token(), referenceTotp(first.enrollment(), step()), totpContext())).isEmpty();
		assertThat(this.replacements.complete(user.id(), second.replacementId(), second.token(), referenceTotp(second.enrollment(), step()), totpContext())).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "replacement", "recovery" })
	void recoveryAndReplacementProofsAreIsolatedAndTheFirstCompletionInvalidatesTheOther(String winner) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var set = issue(factor);
		var recovery = this.recoveries.begin(user.id(), PASSWORD, set.codes().getFirst(), recoveryContext()).orElseThrow();
		var replacement = begin(factor);
		assertThat(this.replacements.complete(user.id(), replacement.replacementId(), recovery.token(),
				referenceTotp(replacement.enrollment(), step()), totpContext())).isEmpty();
		assertThat(this.recoveries.complete(user.id(), recovery.recoveryId(), replacement.token(),
				referenceTotp(recovery.enrollment(), step()), totpContext())).isEmpty();
		if (winner.equals("replacement")) {
			assertThat(this.replacements.complete(user.id(), replacement.replacementId(), replacement.token(), referenceTotp(replacement.enrollment(), step()), totpContext())).isPresent();
			assertThat(this.recoveries.complete(user.id(), recovery.recoveryId(), recovery.token(), referenceTotp(recovery.enrollment(), step()), totpContext())).isEmpty();
		}
		else {
			assertThat(this.recoveries.complete(user.id(), recovery.recoveryId(), recovery.token(), referenceTotp(recovery.enrollment(), step()), totpContext())).isPresent();
			assertThat(this.replacements.complete(user.id(), replacement.replacementId(), replacement.token(), referenceTotp(replacement.enrollment(), step()), totpContext())).isEmpty();
		}
		assertThat(count("iam_totp_replacement")).isZero(); assertThat(count("iam_totp_recovery")).isZero();
		assertThat(count("iam_user_totp")).isEqualTo(1); assertThat(codeRows()).hasSize(10);
	}

	@ParameterizedTest
	@ValueSource(strings = { "begin", "complete" })
	void concurrentCredentialUsePublishesOnlyOneSuccessfulResult(String operation) throws Exception {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		var pending = operation.equals("complete") ? begin(factor) : null;
		String code = referenceTotp(pending == null ? factor : pending.enrollment(), step());
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var tasks = Stream.of(1, 2).map(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				return pending == null ? this.replacements.begin(user.id(), PASSWORD, code, totpContext()).isPresent()
						: this.replacements.complete(user.id(), pending.replacementId(), pending.token(), code, totpContext()).isPresent();
			})).toList();
			start.countDown(); int successes = 0;
			for (var task : tasks) { if (task.get(15, TimeUnit.SECONDS)) { successes++; } }
			assertThat(successes).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password_authenticated", "totp_authenticated", "totp_replacement_started", "browser_sessions_revoked",
			"mfa_recovery_codes_generated", "totp_replacement_completed", "totp_replacement_failed", "totp_replacement_throttled" })
	void requiredAuditFailureRollsBackAllCredentialFactorSessionAndBudgetChanges(String action) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); issue(factor); addSession(user.id());
		boolean starting = List.of("password_authenticated", "totp_authenticated", "totp_replacement_started").contains(action);
		var pending = starting ? null : begin(factor);
		if (action.equals("totp_replacement_throttled")) {
			for (int i = 0; i < 5; i++) { this.replacements.complete(user.id(), pending.replacementId(), "bad", "bad", totpContext()); }
		}
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT replacement_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		try {
			assertThatThrownBy(() -> {
				if (starting) { begin(factor); }
				else { this.replacements.complete(user.id(), pending.replacementId(), pending.token(), action.equals("totp_replacement_failed") ? "bad" : referenceTotp(pending.enrollment(), step()), totpContext()); }
			}).isInstanceOf(DataAccessException.class);
		}
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT replacement_test_reject").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "begin", "complete" })
	void commitFailureNeverDeliversSecretsOrPartialFactorChanges(String operation) {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		var pending = operation.equals("complete") ? begin(factor) : null;
		var before = snapshot(this.jdbc, TABLES);
		this.jdbc.sql("CREATE FUNCTION replacement_test_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit failure'; END $$").update();
		try {
			this.jdbc.sql("CREATE CONSTRAINT TRIGGER replacement_test_commit AFTER INSERT OR DELETE ON iam_totp_replacement DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION replacement_test_commit()").update();
			assertThatThrownBy(() -> {
				if (pending == null) { begin(factor); }
				else { this.replacements.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext()); }
			}).isInstanceOf(TransactionSystemException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION replacement_test_commit() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "grant-insert", "grant-delete", "factor-delete", "factor-insert", "version", "code-insert", "session-delete", "budget", "budget-success" })
	void suppressedMandatoryWritesCannotReturnSuccess(String fault) {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); issue(factor); addSession(user.id());
		var pending = fault.equals("grant-insert") ? null : begin(factor);
		if (fault.equals("budget-success")) { this.replacements.complete(user.id(), pending.replacementId(), "bad", "bad", totpContext()); }
		var before = snapshot(this.jdbc, TABLES);
		String table = switch (fault) {
			case "grant-insert", "grant-delete" -> "iam_totp_replacement";
			case "factor-delete", "factor-insert" -> "iam_user_totp";
			case "version" -> "iam_password";
			case "code-insert" -> "iam_mfa_recovery_code";
			case "session-delete" -> "iam_browser_session";
			default -> "iam_totp_authentication_limit";
		};
		String mutation = fault.endsWith("delete") ? "DELETE" : fault.equals("version") || fault.startsWith("budget") ? "UPDATE" : "INSERT";
		this.jdbc.sql("CREATE FUNCTION replacement_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN " + (mutation.equals("UPDATE") ? "OLD" : "NULL") + "; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER replacement_test_suppress BEFORE " + mutation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION replacement_test_suppress()").update();
			assertThatThrownBy(() -> {
				if (pending == null) { begin(factor); }
				else { this.replacements.complete(user.id(), pending.replacementId(), pending.token(), fault.equals("budget") ? "bad" : referenceTotp(pending.enrollment(), step()), totpContext()); }
			}).isInstanceOf(RuntimeException.class);
		}
		finally { this.jdbc.sql("DROP FUNCTION replacement_test_suppress() CASCADE").update(); }
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void sharesTotpBudgetsAndBoundsNewAccountBucketsWhenThePasswordSourceIsBlocked() {
		for (int i = 0; i < 50; i++) { this.authentications.authenticate("unknown-" + i, "bad", passwordContext()); }
		for (int i = 0; i < 30; i++) { assertThat(this.replacements.begin(UUID.randomUUID(), "bad", "bad", totpContext())).isEmpty(); }
		int accounts = failures("account").size();
		assertThat(failures("source")).containsExactly(30);
		assertThat(this.replacements.begin(UUID.randomUUID(), "bad", "bad", totpContext())).isEmpty();
		assertThat(failures("account")).hasSize(accounts);
		assertThat(events("totp_replacement_throttled")).hasSize(1);
	}

	@Test
	void wrongOldFactorAttemptsBlockOrdinaryVerificationAndCompletionUntilTheSharedWindowResets() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var pending = begin(factor);
		for (int i = 0; i < 5; i++) { assertThat(this.replacements.begin(user.id(), PASSWORD, "bad", totpContext())).isEmpty(); }
		assertThat(this.totps.verify(user.id(), referenceTotp(factor, step() + 1), totpContext())).isEmpty();
		assertThat(this.replacements.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isEmpty();
		this.jdbc.sql("UPDATE iam_totp_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '301 seconds'").update();
		assertThat(this.replacements.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isPresent();
	}

	@Test
	void malformedPendingCiphertextIsASystemFailureAndPreservesTheOldFactor() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var pending = begin(factor);
		this.jdbc.sql("UPDATE iam_totp_replacement SET secret_ciphertext = 'v1.' || repeat('A',64)").update();
		var before = snapshot(this.jdbc, TABLES);
		assertThatThrownBy(() -> this.replacements.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isInstanceOf(IllegalStateException.class);
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void rejectsAmbientTransactionsAndMissingTrustedInputsBeforeCredentialConsumption() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var pending = begin(factor);
		var before = snapshot(this.jdbc, TABLES);
		assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> this.replacements.begin(user.id(), PASSWORD, "bad", totpContext())));
		assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> this.replacements.complete(user.id(), pending.replacementId(), pending.token(), "bad", totpContext())));
		assertThatIllegalArgumentException().isThrownBy(() -> this.replacements.begin(user.id(), PASSWORD, "bad", null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.replacements.complete(user.id(), null, pending.token(), "bad", totpContext()));
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
	}

	@Test
	void restartPreservesPendingProofAndMissingOrWrongKeysFailWithoutConsumingCredentials() {
		var user = activeUser("alice"); var factor = activeFactor(user.id()); var pending = begin(factor);
		var before = snapshot(this.jdbc, TABLES);
		try (var restarted = restart("")) {
			var service = restarted.getBean(IdentityTotpReplacements.class);
			assertThatIllegalStateException().isThrownBy(() -> service.begin(user.id(), PASSWORD, referenceTotp(factor, step() + 1), totpContext()));
			assertThatIllegalStateException().isThrownBy(() -> service.complete(user.id(), pending.replacementId(), pending.token(), "bad", totpContext()));
		}
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
		Path wrongKey = keyFile();
		try (var restarted = restart(wrongKey.toString())) {
			assertThatIllegalStateException().isThrownBy(() -> restarted.getBean(IdentityTotpReplacements.class)
					.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext()));
		}
		finally {
			try { Files.deleteIfExists(wrongKey); }
			catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
		}
		assertThat(snapshot(this.jdbc, TABLES)).isEqualTo(before);
		try (var restarted = restart(KEY_FILE.toString())) {
			assertThat(restarted.getBean(IdentityTotpReplacements.class).complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext())).isPresent();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "expiry", "window" })
	void consumingWriteRechecksDeadlineAndWindowAfterCodeVerification(String boundary) {
		var user = activeUser("alice"); var pending = begin(activeFactor(user.id()));
		doAnswer(call -> {
			if (boundary.equals("expiry")) { expire(user.id()); }
			return java.util.OptionalLong.of(boundary.equals("window") ? step() - 2 : step());
		}).when(this.codes).match(any(byte[].class), anyString(), any(Instant.class), anyLong());
		assertThat(this.replacements.complete(user.id(), pending.replacementId(), pending.token(), "123456", totpContext())).isEmpty();
		assertThat(count("iam_totp_replacement")).isEqualTo(1);
		assertThat(events("totp_replacement_completed")).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "expiry", "version", "disabled" })
	void waitingForTheUserLockRechecksChangedState(String state) throws Exception {
		var user = activeUser("alice"); var pending = begin(activeFactor(user.id()));
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.lockById(user.id()); locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
				if (state.equals("expiry")) { expire(user.id()); }
				else if (state.equals("version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1").update(); }
				else { this.states.disable(user.id(), SYSTEM); }
			}));
			try {
				assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
				var attempt = executor.submit(() -> this.replacements.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext()));
				awaitUserLockWait(); release.countDown(); blocker.get(10, TimeUnit.SECONDS);
				assertThat(attempt.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void cleanupDeletesOnlyExpiredPendingReplacements() {
		var alice = activeUser("alice"); var bob = activeUser("bob");
		begin(activeFactor(alice.id())); begin(activeFactor(bob.id())); expire(alice.id());
		this.replacements.cleanUpExpiredReplacements();
		assertThat(this.jdbc.sql("SELECT user_id FROM iam_totp_replacement").query(UUID.class).list()).containsExactly(bob.id());
		assertThat(count("iam_user_totp")).isEqualTo(2);
	}

	@ParameterizedTest
	@ValueSource(strings = { "credential_version = 0", "new_factor_id = old_factor_id", "token_digest = 'bad'", "key_id = 'bad'", "expires_at = issued_at" })
	void databaseRejectsInvalidReplacementState(String assignment) {
		begin(activeFactor(activeUser("alice").id()));
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_totp_replacement SET " + assignment).update()).isInstanceOf(DataAccessException.class);
	}

	@Test
	void upgradingV14PreservesExistingRowsAndDoesNotInventPendingReplacements() throws Exception {
		String schema = "replacement_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			var client = JdbcClient.create(new SingleConnectionDataSource(connection, true));
			client.sql("SET search_path TO " + schema).update();
			flyway(schema, "14").migrate();
			UUID user = UUID.randomUUID();
			client.sql("INSERT INTO iam_user (id,username,display_name,status) VALUES (:id,'alice','Alice','pending')").param("id", user).update();
			var oldTables = TABLES.stream().filter(t -> !t.equals("iam_totp_replacement")).toList();
			var before = snapshot(client, oldTables);
			flyway(schema, "15").migrate(); flyway(schema, "15").migrate();
			assertThat(snapshot(client, oldTables)).isEqualTo(before);
			assertThat(client.sql("SELECT count(*) FROM iam_totp_replacement").query(Long.class).single()).isZero();
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	@Test
	void passwordRecoveryCodeAndFactorWorkflowsCanRunConcurrentlyWithoutLockInversion() throws Exception {
		var user = activeUser("alice"); var factor = activeFactor(user.id());
		// Seed existing codes so the competing workflows can still submit a fresh factor step.
		var set = new TransactionTemplate(this.transactions).execute(status ->
				this.recoveryCodes.issueForVerifiedFactor(user.id(), factor.factorId(), SYSTEM));
		var pending = begin(factor);
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(5)) {
			var operations = List.<Runnable>of(
					() -> this.replacements.begin(user.id(), PASSWORD, referenceTotp(factor, step() + 1), totpContext()),
					() -> this.replacements.complete(user.id(), pending.replacementId(), pending.token(), referenceTotp(pending.enrollment(), step()), totpContext()),
					() -> this.recoveries.begin(user.id(), PASSWORD, set.codes().getFirst(), recoveryContext()),
					() -> this.recoveryCodes.issue(user.id(), referenceTotp(factor, step() + 1), totpContext()),
					() -> this.authentications.authenticate(user.username(), PASSWORD, passwordContext()));
			var tasks = operations.stream().map(operation -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); operation.run(); return true;
			})).toList();
			start.countDown();
			for (var task : tasks) { assertThat(task.get(15, TimeUnit.SECONDS)).isTrue(); }
		}
		assertThat(count("iam_user_totp")).isEqualTo(1);
		assertThat(codeRows()).hasSize(10);
		assertThat(events("totp_replacement_completed")).hasSizeLessThanOrEqualTo(1);
	}

	@Test
	void cleanupSkipsLockedPendingGrantsWithoutDeletingTheirActiveFactors() throws Exception {
		var user = activeUser("alice"); begin(activeFactor(user.id())); expire(user.id());
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			connection.setAutoCommit(false);
			var locked = JdbcClient.create(new SingleConnectionDataSource(connection, true));
			locked.sql("SELECT user_id FROM iam_totp_replacement WHERE user_id = :id FOR UPDATE").param("id", user.id()).query(UUID.class).single();
			try (var executor = Executors.newSingleThreadExecutor()) {
				executor.submit(() -> this.replacements.cleanUpExpiredReplacements()).get(5, TimeUnit.SECONDS);
			}
			assertThat(count("iam_totp_replacement")).isEqualTo(1);
			connection.rollback();
		}
		this.replacements.cleanUpExpiredReplacements();
		assertThat(count("iam_totp_replacement")).isZero();
		assertThat(count("iam_user_totp")).isEqualTo(1);
	}

	@Test
	void cleanupIsBoundedAndLeavesAllActiveFactorsUntouched() {
		var user = activeUser("alice"); begin(activeFactor(user.id())); expire(user.id());
		this.jdbc.sql("INSERT INTO iam_user (id,username,display_name,status) SELECT gen_random_uuid(), 'extra-' || i, 'Extra', 'active' FROM generate_series(1,1000) i").update();
		this.jdbc.sql("""
				INSERT INTO iam_user_totp (user_id, factor_id, secret_ciphertext, key_id, enrollment_credential_version,
				    status, issued_at, expires_at, activated_at, last_used_step)
				SELECT u.id, gen_random_uuid(), t.secret_ciphertext, t.key_id, 1, 'active', t.issued_at, t.expires_at, t.activated_at, t.last_used_step
				FROM iam_user u CROSS JOIN iam_user_totp t WHERE t.user_id = :id AND u.id <> :id
				""").param("id", user.id()).update();
		this.jdbc.sql("""
				INSERT INTO iam_totp_replacement (user_id, replacement_id, old_factor_id, new_factor_id, credential_version,
				    token_digest, secret_ciphertext, key_id, issued_at, expires_at)
				SELECT t.user_id, gen_random_uuid(), t.factor_id, gen_random_uuid(), 1,
				    r.token_digest, r.secret_ciphertext, r.key_id, r.issued_at, r.expires_at
				FROM iam_user_totp t CROSS JOIN iam_totp_replacement r WHERE r.user_id = :id AND t.user_id <> :id
				""").param("id", user.id()).update();
		assertThat(count("iam_totp_replacement")).isEqualTo(1001);
		this.replacements.cleanUpExpiredReplacements();
		assertThat(count("iam_totp_replacement")).isEqualTo(1);
		this.replacements.cleanUpExpiredReplacements();
		assertThat(count("iam_totp_replacement")).isZero();
		assertThat(count("iam_user_totp")).isEqualTo(1001);
	}

	private org.springframework.context.ConfigurableApplicationContext restart(String key) {
		return new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
				"spring.datasource.password", this.postgres.getPassword())).run("--iam.totp.key-file=" + key);
	}

	private IdentityTotpReplacement begin(IdentityTotpEnrollment factor) {
		return this.replacements.begin(factor.userId(), PASSWORD, freshTotp(factor), totpContext()).orElseThrow();
	}

	private void expire(UUID userId) {
		this.jdbc.sql("UPDATE iam_totp_replacement SET issued_at = t.now - INTERVAL '11 minutes', expires_at = t.now - INTERVAL '1 minute' FROM (SELECT clock_timestamp() AS now) t WHERE user_id = :id")
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
				// Activation fixtures keep these tests focused on replacement workflows; confirmation has its own integration coverage.
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
		return new TotpAuthenticationContext("internal:totp-replacement", recovery.clientAddress(), UUID.randomUUID());
	}

	private static MfaRecoveryCodeContext recoveryContext() { return recoveryContext("192.0.2.100"); }

	private static MfaRecoveryCodeContext recoveryContext(String address) {
		try { return new MfaRecoveryCodeContext("internal:totp-replacement", InetAddress.getByName(address), UUID.randomUUID()); }
		catch (Exception ex) { throw new IllegalStateException(ex); }
	}

	private static Path keyFile() {
		try {
			byte[] key = new byte[32];
			new SecureRandom().nextBytes(key);
			Path file = Files.createTempFile("iam-totp-replacement-test-", ".key");
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
		throw new AssertionError("TOTP replacement did not reach the user lock");
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
