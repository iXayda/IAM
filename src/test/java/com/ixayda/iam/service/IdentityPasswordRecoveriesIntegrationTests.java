package com.ixayda.iam.service;

import java.net.InetAddress;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.credential.PasswordRecoveryTokens;
import com.ixayda.iam.model.IdentityPasswordRecovery;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.service.IdentityPasswordRecoveries.Result.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityPasswordRecoveriesIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the Café";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final String SOURCE = "internal:recovery-test";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:recovery-test", SOURCE, UUID.randomUUID());

	@Autowired
	private IdentityPasswordRecoveries recoveries;
	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private IdentityPasswords changes;
	@Autowired
	private PasswordRecoveryTokens tokens;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private PlatformTransactionManager transactions;
	@Autowired
	private DataSource dataSource;
	@Autowired
	private PostgreSQLContainer postgres;
	@MockitoSpyBean
	private PasswordHasher passwords;

	@BeforeEach
	@AfterEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_recovery",
				"iam_password_authentication_limit", "iam_security_audit", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void issuesAVersionBoundDigestWithDatabaseExpiryAndRedactsTheDeliveryValue() {
		var user = activeUser("alice");
		Instant before = Instant.now();
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		assertThat(proof.userId()).isEqualTo(user.id());
		assertThat(proof.token()).hasSize(43);
		assertThat(proof.expiresAt()).isBetween(before.plusSeconds(1800), Instant.now().plusSeconds(1800));
		var row = proofRow(user.id());
		assertThat(row.get("token_digest")).isEqualTo(this.tokens.digest(proof.token()));
		assertThat(row.get("credential_version")).isEqualTo(1L);
		assertThat(row.get("status")).isEqualTo("issued");
		assertThat(row.get("finished_at")).isNull();
		assertThat(Duration.between(proofInstant(user.id(), "issued_at"), proof.expiresAt())).isEqualTo(Duration.ofMinutes(30));
		assertThat(proof.toString()).contains("[REDACTED]").doesNotContain(proof.token());
		assertNoSecrets(proof);
		assertThat(version(user.id())).isEqualTo(1);
		assertThat(count("password_recovery_issued")).isEqualTo(1);
	}

	@Test
	void transactionalConsumptionRequiresATransactionAndRollsBackWithItsCaller() {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		assertThatThrownBy(() -> this.recoveries.completeInTransaction(user.id(), proof.token(), NEW_PASSWORD, SYSTEM))
				.isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			assertThat(this.recoveries.completeInTransaction(user.id(), proof.token(), NEW_PASSWORD, SYSTEM)).isEqualTo(COMPLETED);
			status.setRollbackOnly();
		});
		assertThat(version(user.id())).isEqualTo(1);
		assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
		assertThat(count("password_recovery_completed")).isZero();
		assertThat(complete(proof)).isEqualTo(COMPLETED);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void managementIssuanceRequiresATransactionAndRollsBackWithItsCaller(boolean replacing) {
		var user = activeUser("alice");
		var previous = replacing ? this.recoveries.issue(user.id(), SYSTEM) : null;
		long issued = count("password_recovery_issued");
		assertThatThrownBy(() -> this.recoveries.issueInTransaction(user.id(), SYSTEM))
				.isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			var proof = this.recoveries.issueInTransaction(user.id(), SYSTEM);
			assertThat(proofRow(user.id()).get("token_digest")).isEqualTo(this.tokens.digest(proof.token()));
			status.setRollbackOnly();
		});
		assertThat(count("password_recovery_issued")).isEqualTo(issued);
		if (previous == null) {
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_recovery").query(Long.class).single()).isZero();
		}
		else {
			assertThat(proofRow(user.id()).get("token_digest")).isEqualTo(this.tokens.digest(previous.token()));
			assertThat(this.recoveries.complete(user.id(), previous.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(COMPLETED);
		}
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 125 })
	void recoveryAtomicallyReplacesThePasswordAndRevokesAllOwnedSessionsIncludingZero(int sessionCount) {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		String bobHash = hash(bob.id());
		for (int i = 0; i < sessionCount; i++) { session(alice.id()); }
		session(bob.id());
		var proof = this.recoveries.issue(alice.id(), SYSTEM);
		UUID correlation = UUID.randomUUID();
		assertThat(this.recoveries.complete(alice.id(), proof.token(), NEW_PASSWORD, SOURCE, correlation)).isEqualTo(COMPLETED);
		assertThat(version(alice.id())).isEqualTo(2);
		assertThat(this.passwords.matches(NEW_PASSWORD, hash(alice.id()))).isTrue();
		assertThat(this.passwords.matches(PASSWORD, hash(alice.id()))).isFalse();
		assertThat(proofRow(alice.id()).get("status")).isEqualTo("consumed");
		assertThat(sessionCount(alice.id())).isZero();
		assertThat(sessionCount(bob.id())).isEqualTo(1);
		assertThat(hash(bob.id())).isEqualTo(bobHash);
		var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('password_recovery_completed', 'browser_sessions_revoked')")
				.query().listOfRows();
		assertThat(events).hasSize(2).allSatisfy(event -> {
			assertThat(event.get("actor")).isEqualTo("user:" + alice.id());
			assertThat(event.get("target_user_id")).isEqualTo(alice.id());
			assertThat(event.get("source")).isEqualTo(SOURCE);
			assertThat(event.get("correlation_id")).isEqualTo(correlation);
			assertThat(event.get("outcome")).isEqualTo("success");
		});
		assertThat(count("browser_session_ended")).isZero();
		assertThat(count("password_changed")).isZero();
		assertNoSecrets(proof);
		assertThat(complete(proof)).isEqualTo(INVALID_PROOF);
		assertThat(version(alice.id())).isEqualTo(2);
	}

	@Test
	void reissueAndCancellationInvalidateOldProofsAndDoNotChangeThePassword() {
		var user = activeUser("alice");
		var first = this.recoveries.issue(user.id(), SYSTEM);
		var replacement = this.recoveries.issue(user.id(), SYSTEM);
		assertThat(complete(first)).isEqualTo(INVALID_PROOF);
		this.recoveries.cancel(user.id(), SYSTEM);
		assertThat(proofRow(user.id()).get("status")).isEqualTo("cancelled");
		assertThat(complete(replacement)).isEqualTo(INVALID_PROOF);
		assertThatIllegalStateException().isThrownBy(() -> this.recoveries.cancel(user.id(), SYSTEM));
		assertThat(version(user.id())).isEqualTo(1);
		assertThat(complete(this.recoveries.issue(user.id(), SYSTEM))).isEqualTo(COMPLETED);
		assertThatIllegalStateException().isThrownBy(() -> this.recoveries.cancel(user.id(), SYSTEM));
	}

	@Test
	void bindsProofsToTheAccountAndPurposeAndNeverActivatesPendingUsers() {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		var pending = this.users.create("carol", "Carol", SYSTEM);
		var setup = this.setups.issue(pending.id(), SYSTEM);
		var proof = this.recoveries.issue(alice.id(), SYSTEM);
		this.recoveries.issue(bob.id(), SYSTEM);
		assertThat(this.recoveries.complete(bob.id(), proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(INVALID_PROOF);
		assertThat(this.recoveries.complete(alice.id(), setup.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(INVALID_PROOF);
		assertThat(this.recoveries.complete(pending.id(), setup.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(INVALID_PROOF);
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(pending.id(), proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID()));
		assertThat(this.users.findById(pending.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.PENDING);
		assertThat(version(alice.id())).isEqualTo(1);
		assertThat(version(bob.id())).isEqualTo(1);
		assertThat(complete(proof)).isEqualTo(COMPLETED);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "bad", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" })
	void invalidProofsAreAuditedAnonymouslyWithoutPasswordWork(String token) {
		var user = activeUser("alice");
		this.recoveries.issue(user.id(), SYSTEM);
		clearInvocations(this.passwords);
		assertThat(this.recoveries.complete(user.id(), token, NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(INVALID_PROOF);
		verify(this.passwords, never()).matches(any(), any());
		verify(this.passwords, never()).hash(any(), any());
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = 'password_recovery_failed'").query().singleRow();
		assertThat(event.get("actor")).isEqualTo("anonymous");
		assertThat(event.get("target_user_id")).isEqualTo(user.id());
		assertThat(version(user.id())).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "pending", "disabled", "no-password" })
	void requiresAnActiveExistingUserWithPasswordForIssuanceAndCompletion(String state) {
		var user = state.equals("pending") ? this.users.create("alice", "Alice", SYSTEM) : activeUser("alice");
		UUID id = state.equals("missing") ? UUID.randomUUID() : user.id();
		String proof = this.tokens.generate();
		if (!state.equals("pending")) { proof = this.recoveries.issue(user.id(), SYSTEM).token(); }
		if (state.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status = 'disabled'").update(); }
		if (state.equals("no-password")) { this.jdbc.sql("DELETE FROM iam_password").update(); }
		assertThatThrownBy(() -> this.recoveries.issue(id, SYSTEM)).isInstanceOf(RuntimeException.class);
		clearInvocations(this.passwords);
		assertThat(this.recoveries.complete(id, proof, NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(INVALID_PROOF);
		verify(this.passwords, never()).hash(any(), any());
		assertThat(count("password_recovery_completed")).isZero();
		if (state.equals("missing")) {
			assertThat(this.jdbc.sql("SELECT target_user_id FROM iam_security_audit WHERE action = 'password_recovery_failed'")
					.query().singleRow().get("target_user_id")).isNull();
		}
		if (state.equals("disabled")) {
			this.recoveries.cancel(id, SYSTEM);
			assertThat(this.users.findById(id).orElseThrow().status()).isEqualTo(IdentityUser.Status.DISABLED);
		}
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "short", "passwordpassword", PASSWORD, "Seven amber lanterns beside the Cafe\u0301" })
	void invalidOrUnchangedPasswordsPreserveTheProofForRetry(String password) {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		assertThat(this.recoveries.complete(user.id(), proof.token(), password, SOURCE, UUID.randomUUID())).isEqualTo(INVALID_PASSWORD);
		assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
		assertThat(version(user.id())).isEqualTo(1);
		assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action = 'password_recovery_failed'").query(String.class).single())
				.isEqualTo("user:" + user.id());
		assertThat(complete(proof)).isEqualTo(COMPLETED);
	}

	@Test
	void passwordChangesInvalidatePreviouslyIssuedRecoveryProofs() throws Exception {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String session = session(user.id());
		assertThat(this.changes.change(user.id(), session, 1, System.currentTimeMillis(), PASSWORD, NEW_PASSWORD,
				new PasswordAuthenticationContext("internal:password-change", InetAddress.getLoopbackAddress(), UUID.randomUUID())))
				.isEqualTo(IdentityPasswords.Result.CHANGED);
		clearInvocations(this.passwords);
		assertThat(complete(proof)).isEqualTo(INVALID_PROOF);
		verify(this.passwords, never()).hash(any(), any());
		assertThat(version(user.id())).isEqualTo(2);
		assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
	}

	@ParameterizedTest
	@ValueSource(strings = { "before", "hashing", "storage" })
	void expiredProofsCannotChangeCredentialsEvenWhenExpiryCrossesDuringWork(String when) {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String original = hash(user.id());
		if (when.equals("before")) {
			this.jdbc.sql("UPDATE iam_password_recovery SET expires_at = clock_timestamp()").update();
		}
		else if (when.equals("hashing")) {
			this.jdbc.sql("UPDATE iam_password_recovery SET expires_at = clock_timestamp() + INTERVAL '1 second'").update();
			Instant deadline = proofInstant(user.id(), "expires_at");
			doAnswer(call -> {
				Object hash = call.callRealMethod();
				await().atMost(Duration.ofSeconds(3)).until(() -> Instant.now().isAfter(deadline));
				return hash;
			}).when(this.passwords).hash(eq(NEW_PASSWORD), eq("alice"));
		}
		else { installFault("iam_password", "AFTER UPDATE", "UPDATE iam_password_recovery SET expires_at = clock_timestamp(); RETURN NEW;", false); }
		try { assertThat(complete(proof)).isEqualTo(INVALID_PROOF); }
		finally { if (when.equals("storage")) { removeFault("iam_password"); } }
		assertThat(hash(user.id())).isEqualTo(original);
		assertThat(version(user.id())).isEqualTo(1);
		assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
		assertThat(count("password_recovery_failed")).isEqualTo(1);
		assertThat(count("password_recovery_completed")).isZero();
		if (when.equals("storage")) {
			assertThat(proofInstant(user.id(), "expires_at")).isEqualTo(proof.expiresAt());
			assertThat(complete(proof)).isEqualTo(COMPLETED);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel", "complete" })
	void rejectsAmbientTransactionsBeforeAnyMutation(String operation) {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		long auditCount = total("iam_security_audit");
		new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				assertThatIllegalStateException().isThrownBy(() -> {
					switch (operation) {
						case "issue" -> this.recoveries.issue(user.id(), SYSTEM);
						case "cancel" -> this.recoveries.cancel(user.id(), SYSTEM);
						default -> complete(proof);
					}
				}).withMessage("Password recovery requires an independent transaction"));
		assertThat(proofRow(user.id()).get("token_digest")).isEqualTo(this.tokens.digest(proof.token()));
		assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
		assertThat(total("iam_security_audit")).isEqualTo(auditCount);
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "retained-hash", "retained-version", "consume", "retained-proof", "sessions",
			"partial-sessions", "completed-audit", "revoke-audit", "silent-audit", "deferred-audit" })
	void faultsRollBackPasswordProofSessionsAndSuccessAudit(String fault) {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String original = hash(user.id());
		session(user.id()); session(user.id());
		String table = fault.equals("password") || fault.startsWith("retained-") && !fault.equals("retained-proof") ? "iam_password"
				: fault.equals("consume") || fault.equals("retained-proof") ? "iam_password_recovery"
				: fault.contains("sessions") ? "iam_browser_session" : "iam_security_audit";
		String body = switch (fault) {
			case "retained-hash" -> "NEW.password_hash := OLD.password_hash; RETURN NEW;";
			case "retained-version" -> "NEW.credential_version := OLD.credential_version; RETURN NEW;";
			case "retained-proof" -> "NEW.status := OLD.status; NEW.finished_at := OLD.finished_at; RETURN NEW;";
			case "consume" -> "RETURN NULL;";
			case "partial-sessions" -> "IF OLD.primary_id = (SELECT min(primary_id) FROM iam_browser_session) THEN RETURN NULL; END IF; RETURN OLD;";
			case "silent-audit" -> "IF NEW.action = 'password_recovery_completed' THEN RETURN NULL; END IF; RETURN NEW;";
			case "completed-audit", "deferred-audit" -> "IF NEW.action = 'password_recovery_completed' THEN RAISE EXCEPTION 'recovery fault'; END IF; RETURN NEW;";
			case "revoke-audit" -> "IF NEW.action = 'browser_sessions_revoked' THEN RAISE EXCEPTION 'recovery fault'; END IF; RETURN NEW;";
			default -> "RAISE EXCEPTION 'recovery fault';";
		};
		installFault(table, (fault.equals("deferred-audit") ? "AFTER " : "BEFORE ")
				+ (table.equals("iam_security_audit") ? "INSERT" : table.equals("iam_browser_session") ? "DELETE" : "UPDATE"),
				body, fault.equals("deferred-audit"));
		try {
			assertThatThrownBy(() -> complete(proof)).isInstanceOf(RuntimeException.class);
			assertThat(hash(user.id())).isEqualTo(original);
			assertThat(version(user.id())).isEqualTo(1);
			assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
			assertThat(sessionCount(user.id())).isEqualTo(2);
			assertThat(count("password_recovery_completed")).isZero();
			assertThat(count("browser_sessions_revoked")).isZero();
		}
		finally { removeFault(table); }
		assertThat(complete(proof)).isEqualTo(COMPLETED);
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel", "failure-audit", "deferred-issue" })
	void auditFailureNeverReturnsAnUncommittedSecretOrDenial(String operation) {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String action = operation.equals("cancel") ? "password_recovery_cancelled"
				: operation.equals("failure-audit") ? "password_recovery_failed" : "password_recovery_issued";
		installFault("iam_security_audit", operation.equals("deferred-issue") ? "AFTER INSERT" : "BEFORE INSERT",
				"IF NEW.action = '" + action + "' THEN RAISE EXCEPTION 'recovery audit fault'; END IF; RETURN NEW;", operation.equals("deferred-issue"));
		try {
			assertThatThrownBy(() -> {
				switch (operation) {
					case "cancel" -> this.recoveries.cancel(user.id(), SYSTEM);
					case "failure-audit" -> this.recoveries.complete(user.id(), this.tokens.generate(), NEW_PASSWORD, SOURCE, UUID.randomUUID());
					default -> this.recoveries.issue(user.id(), SYSTEM);
				}
			}).isInstanceOf(RuntimeException.class);
			assertThat(proofRow(user.id()).get("token_digest")).isEqualTo(this.tokens.digest(proof.token()));
			assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
			assertThat(count("password_recovery_issued")).isEqualTo(1);
			assertThat(count("password_recovery_failed")).isZero();
		}
		finally { removeFault("iam_security_audit"); }
		assertThat(complete(proof)).isEqualTo(COMPLETED);
	}

	@Test
	void concurrentConsumersHaveExactlyOneWinner() throws Exception {
		var proof = this.recoveries.issue(activeUser("alice").id(), SYSTEM);
		assertThat(race(() -> complete(proof), () -> complete(proof))).containsExactlyInAnyOrder(COMPLETED, INVALID_PROOF);
		assertThat(version(proof.userId())).isEqualTo(2);
		assertThat(count("password_recovery_completed")).isEqualTo(1);
		assertThat(count("password_recovery_failed")).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "silent-issue", "retained-issue", "silent-cancel", "retained-cancel" })
	void silentIssuanceOrCancellationCannotReturnSuccess(String fault) {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String body = fault.startsWith("silent") ? "RETURN NULL;" : fault.endsWith("issue")
				? "NEW.token_digest := OLD.token_digest; RETURN NEW;"
				: "NEW.status := OLD.status; NEW.finished_at := OLD.finished_at; RETURN NEW;";
		installFault("iam_password_recovery", "BEFORE UPDATE", body, false);
		try {
			assertThatThrownBy(() -> {
				if (fault.endsWith("issue")) { this.recoveries.issue(user.id(), SYSTEM); }
				else { this.recoveries.cancel(user.id(), SYSTEM); }
			}).isInstanceOf(RuntimeException.class);
			assertThat(proofRow(user.id()).get("token_digest")).isEqualTo(this.tokens.digest(proof.token()));
			assertThat(proofRow(user.id()).get("status")).isEqualTo("issued");
			assertThat(count("password_recovery_issued")).isEqualTo(1);
			assertThat(count("password_recovery_cancelled")).isZero();
		}
		finally { removeFault("iam_password_recovery"); }
		assertThat(complete(proof)).isEqualTo(COMPLETED);
	}

	@Test
	void requiresValidTrustedContextBeforeAnyWrite() {
		var user = activeUser("alice");
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.issue(null, SYSTEM));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.issue(user.id(), null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.cancel(null, SYSTEM));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.cancel(user.id(), null));
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		long before = total("iam_security_audit");
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.complete(null, proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.complete(user.id(), proof.token(), NEW_PASSWORD, null, UUID.randomUUID()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.recoveries.complete(user.id(), proof.token(), NEW_PASSWORD, SOURCE, null));
		assertThat(total("iam_security_audit")).isEqualTo(before);
		assertThat(version(user.id())).isEqualTo(1);
	}

	@Test
	void reissueAndConsumptionSerializeWithoutRevivingTheOldProof() throws Exception {
		var user = activeUser("alice");
		var old = this.recoveries.issue(user.id(), SYSTEM);
		var replacement = new java.util.concurrent.atomic.AtomicReference<IdentityPasswordRecovery>();
		var result = race(() -> { replacement.set(this.recoveries.issue(user.id(), SYSTEM)); return "issued"; }, () -> complete(old).name());
		assertThat(result.getFirst()).isEqualTo("issued");
		assertThat(result.getLast()).isIn("COMPLETED", "INVALID_PROOF");
		assertThat(complete(old)).isEqualTo(INVALID_PROOF);
		long expectedVersion = result.getLast().equals("COMPLETED") ? 2 : 1;
		assertThat(version(user.id())).isEqualTo(expectedVersion);
		assertThat(this.recoveries.complete(user.id(), replacement.get().token(), "Copper boats beside the mountain", SOURCE, UUID.randomUUID()))
				.isEqualTo(COMPLETED);
		assertThat(version(user.id())).isEqualTo(expectedVersion + 1);
	}

	@Test
	void cancellationAndConsumptionSerialize() throws Exception {
		var proof = this.recoveries.issue(activeUser("alice").id(), SYSTEM);
		var result = race(() -> {
			try { this.recoveries.cancel(proof.userId(), SYSTEM); return "cancelled"; }
			catch (IllegalStateException ex) { return "already-consumed"; }
		}, () -> complete(proof).name());
		if (result.getFirst().equals("cancelled")) {
			assertThat(result.getLast()).isEqualTo("INVALID_PROOF");
			assertThat(version(proof.userId())).isEqualTo(1);
		}
		else {
			assertThat(result).containsExactly("already-consumed", "COMPLETED");
			assertThat(version(proof.userId())).isEqualTo(2);
		}
		assertThat(complete(proof)).isEqualTo(INVALID_PROOF);
	}

	@Test
	void concurrentReissueLeavesOnlyTheLastSerializedProofUsable() throws Exception {
		var user = activeUser("alice");
		var proofs = race(() -> this.recoveries.issue(user.id(), SYSTEM), () -> this.recoveries.issue(user.id(), SYSTEM));
		String digest = (String) proofRow(user.id()).get("token_digest");
		var current = proofs.stream().filter(p -> this.tokens.digest(p.token()).equals(digest)).findFirst().orElseThrow();
		var stale = proofs.stream().filter(p -> p != current).findFirst().orElseThrow();
		assertThat(complete(stale)).isEqualTo(INVALID_PROOF);
		assertThat(complete(current)).isEqualTo(COMPLETED);
	}

	@Test
	void passwordChangeAndRecoveryCannotBothReplaceTheSameVersion() throws Exception {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		String session = session(user.id());
		var context = new PasswordAuthenticationContext("internal:password-change", InetAddress.getLoopbackAddress(), UUID.randomUUID());
		var result = race(() -> this.changes.change(user.id(), session, 1, System.currentTimeMillis(), PASSWORD, NEW_PASSWORD, context).name(),
				() -> complete(proof).name());
		assertThat(result).isIn(List.of("CHANGED", "INVALID_PROOF"), List.of("INVALID_SESSION", "COMPLETED"));
		assertThat(version(user.id())).isEqualTo(2);
		assertThat(sessionCount(user.id())).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "expire", "disable", "version", "cancel", "replace" })
	void rechecksStateAfterWaitingForTheUserLock(String change) throws Exception {
		var user = activeUser("alice");
		var proof = this.recoveries.issue(user.id(), SYSTEM);
		try (var blocker = this.dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try (var statement = blocker.prepareStatement("SELECT id FROM iam_user WHERE id = ? FOR UPDATE")) {
				statement.setObject(1, user.id());
				try (var result = statement.executeQuery()) { assertThat(result.next()).isTrue(); }
			}
			var waiting = executor.submit(() -> complete(proof));
			try {
				await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(this.jdbc.sql("""
						SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
						AND wait_event_type = 'Lock' AND query LIKE '%FROM iam_user WHERE id = %FOR UPDATE%'
						""").query(Long.class).single()).isEqualTo(1));
				String sql = switch (change) {
					case "expire" -> "UPDATE iam_password_recovery SET expires_at = clock_timestamp() WHERE user_id = ?";
					case "disable" -> "UPDATE iam_user SET status = 'disabled' WHERE id = ?";
					case "version" -> "UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = ?";
					case "cancel" -> "UPDATE iam_password_recovery SET status = 'cancelled', finished_at = clock_timestamp() WHERE user_id = ?";
					default -> "UPDATE iam_password_recovery SET token_digest = repeat('0', 64) WHERE user_id = ?";
				};
				try (var statement = blocker.prepareStatement(sql)) { statement.setObject(1, user.id()); statement.executeUpdate(); }
				blocker.commit();
				assertThat(waiting.get(20, TimeUnit.SECONDS)).isEqualTo(INVALID_PROOF);
			}
			finally { blocker.rollback(); }
		}
		assertThat(count("password_recovery_completed")).isZero();
		assertThat(this.passwords.matches(PASSWORD, hash(user.id()))).isTrue();
	}

	@Test
	void aNewApplicationInstanceCanConsumeThePersistedProof() {
		var proof = this.recoveries.issue(activeUser("alice").id(), SYSTEM);
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE)
				.properties(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
						"spring.datasource.password", this.postgres.getPassword(), "spring.main.banner-mode", "off")).run()) {
			assertThat(restarted.getBean(IdentityPasswordRecoveries.class).complete(proof.userId(), proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID()))
					.isEqualTo(COMPLETED);
		}
		assertThat(version(proof.userId())).isEqualTo(2);
	}

	@Test
	void upgradesV6WithoutChangingExistingRowsAndEnforcesRecoveryConstraints() throws Exception {
		String schema = "recovery_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "6").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				JdbcClient previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID user = UUID.randomUUID();
				String id = UUID.randomUUID().toString();
				previous.sql("INSERT INTO iam_user (id, username, display_name, status) VALUES (:id, 'alice', 'Alice', 'active')").param("id", user).update();
				previous.sql("INSERT INTO iam_password (user_id, password_hash, credential_version) VALUES (:id, :hash, 3)")
						.param("id", user).param("hash", this.passwords.hash(PASSWORD, "alice")).update();
				previous.sql("INSERT INTO iam_user_setup VALUES (:id, repeat('a', 64), 'consumed', clock_timestamp(), clock_timestamp() + INTERVAL '30 minutes', clock_timestamp())")
						.param("id", user).update();
				previous.sql("INSERT INTO iam_password_authentication_limit (dimension, subject_key, failures) VALUES ('source', repeat('b', 64), 7)").update();
				previous.sql("INSERT INTO iam_browser_session VALUES (:id, :id, 1, 1, 1800, 1800001, :principal)").param("id", id).param("principal", user.toString()).update();
				previous.sql("INSERT INTO iam_browser_session_attributes VALUES (:id, 'upgrade-marker', :bytes)").param("id", id).param("bytes", new byte[] {1}).update();
				previous.sql("INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome) VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, 'user_created', 'success')")
						.param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", user).update();
				var tables = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_authentication_limit", "iam_browser_session", "iam_browser_session_attributes", "iam_security_audit");
				var before = tables.stream().map(t -> previous.sql("SELECT to_jsonb(t)::text FROM " + t + " t").query(String.class).single()).toList();
				flyway(schema, "7").migrate();
				assertThat(tables.stream().map(t -> previous.sql("SELECT to_jsonb(t)::text FROM " + t + " t").query(String.class).single()).toList()).isEqualTo(before);
				assertThat(previous.sql("SELECT count(*) FROM iam_password_recovery").query(Long.class).single()).isZero();
				previous.sql("INSERT INTO iam_password_recovery (user_id, token_digest, credential_version, status, issued_at, expires_at) VALUES (:user, repeat('c', 64), 3, 'issued', clock_timestamp(), clock_timestamp() + INTERVAL '30 minutes')")
						.param("user", user).update();
				for (String sql : List.of("UPDATE iam_password_recovery SET credential_version = 0", "UPDATE iam_password_recovery SET token_digest = 'invalid'",
						"UPDATE iam_password_recovery SET status = 'consumed'", "UPDATE iam_password_recovery SET expires_at = issued_at",
						"UPDATE iam_password_recovery SET finished_at = clock_timestamp()", "UPDATE iam_password_recovery SET expires_at = 'infinity'")) {
					assertThatThrownBy(() -> previous.sql(sql).update()).isInstanceOf(DataIntegrityViolationException.class);
				}
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET action = 'password_recovery_completed', outcome = 'failure'").update()).isInstanceOf(DataIntegrityViolationException.class);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET action = 'password_recovery_issued', target_user_id = NULL").update()).isInstanceOf(DataIntegrityViolationException.class);
				previous.sql("UPDATE iam_security_audit SET action = 'password_recovery_failed', outcome = 'failure', target_user_id = NULL").update();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private IdentityUser activeUser(String name) {
		var user = this.users.create(name, "Alice", SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), setup.token(), PASSWORD, SOURCE, UUID.randomUUID());
		return this.users.findById(user.id()).orElseThrow();
	}

	private IdentityPasswordRecoveries.Result complete(IdentityPasswordRecovery proof) {
		return this.recoveries.complete(proof.userId(), proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID());
	}

	private Map<String, Object> proofRow(UUID id) {
		return this.jdbc.sql("SELECT * FROM iam_password_recovery WHERE user_id = :id").param("id", id).query().singleRow();
	}

	private Instant proofInstant(UUID id, String column) {
		return this.jdbc.sql("SELECT " + column + " FROM iam_password_recovery WHERE user_id = :id").param("id", id)
				.query(OffsetDateTime.class).single().toInstant();
	}

	private String hash(UUID id) { return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", id).query(String.class).single(); }
	private long version(UUID id) { return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", id).query(Long.class).single(); }
	private long count(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action").param("action", action).query(Long.class).single(); }
	private long total(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }
	private long sessionCount(UUID id) { return this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", id.toString()).query(Long.class).single(); }

	private String session(UUID userId) {
		String id = UUID.randomUUID().toString();
		long now = System.currentTimeMillis();
		this.jdbc.sql("INSERT INTO iam_browser_session VALUES (:id, :id, :now, :now, 1800, :expiry, :principal)")
				.param("id", id).param("now", now).param("expiry", now + 1800000).param("principal", userId.toString()).update();
		this.jdbc.sql("INSERT INTO iam_browser_session_attributes VALUES (:id, 'test-marker', :bytes)").param("id", id).param("bytes", new byte[] {1}).update();
		return id;
	}

	private void assertNoSecrets(IdentityPasswordRecovery proof) {
		for (String table : List.of("iam_password_recovery", "iam_security_audit")) {
			assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t").query(String.class).list())
					.allSatisfy(row -> assertThat(row).doesNotContain(proof.token(), PASSWORD, NEW_PASSWORD, hash(proof.userId())));
		}
	}

	private void installFault(String table, String timing, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION recovery_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER" : "CREATE TRIGGER") + " recovery_test_fault " + timing + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION recovery_test_fault()").update();
	}

	private void removeFault(String table) {
		this.jdbc.sql("DROP TRIGGER IF EXISTS recovery_test_fault ON " + table).update();
		this.jdbc.sql("DROP FUNCTION recovery_test_fault()").update();
	}

	private <T> List<T> race(Callable<T> first, Callable<T> second) throws Exception {
		try (var executor = Executors.newFixedThreadPool(2)) {
			var start = new CountDownLatch(1);
			var a = executor.submit(() -> { assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return first.call(); });
			var b = executor.submit(() -> { assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return second.call(); });
			start.countDown();
			return List.of(a.get(20, TimeUnit.SECONDS), b.get(20, TimeUnit.SECONDS));
		}
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
