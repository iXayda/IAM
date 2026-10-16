package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.AccountSetupTokens;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.credential.PasswordRejectedException;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserSetup;
import com.ixayda.iam.model.SecurityAuditContext;

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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserSetupsIntegrationTests {

	private static final String PASSWORD = "seven amber lanterns by the river";

	private static final String SECOND_PASSWORD = "seven silver lanterns on the hill";

	private static final String SOURCE = "internal:setup-test";

	private final SecurityAuditContext audit = new SecurityAuditContext("system:setup-test", SOURCE, UUID.randomUUID());

	@Autowired
	private IdentityUsers users;

	@Autowired
	private IdentityUserSetups setups;

	@Autowired
	private JdbcClient jdbc;

	@Autowired
	private PasswordHasher passwords;

	@Autowired
	private AccountSetupTokens tokens;

	@Autowired
	private DataSource dataSource;

	@Autowired
	private PlatformTransactionManager transactions;

	@Autowired
	private PostgreSQLContainer postgres;

	@BeforeEach
	void removeTestData() {
		this.jdbc.sql("DELETE FROM iam_security_audit").update();
		this.jdbc.sql("DELETE FROM iam_user_setup").update();
		this.jdbc.sql("DELETE FROM iam_password").update();
		this.jdbc.sql("DELETE FROM iam_user").update();
	}

	@Test
	void issuesOnlyADigestWithDatabaseExpiryAndRedactsTheDeliveryValue() {
		IdentityUser user = createUser();
		Instant before = Instant.now();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		assertThat(proof.userId()).isEqualTo(user.id());
		assertThat(proof.token()).hasSize(43);
		assertThat(proof.expiresAt()).isBetween(before.plusSeconds(1800), Instant.now().plusSeconds(1800));
		var row = this.jdbc.sql("SELECT * FROM iam_user_setup").query().singleRow();
		assertThat(row.get("token_digest")).isEqualTo(this.tokens.digest(proof.token()));
		assertThat(row.get("status")).isEqualTo("issued");
		assertThat(row.get("finished_at")).isNull();
		Instant issuedAt = this.jdbc.sql("SELECT issued_at FROM iam_user_setup").query(OffsetDateTime.class).single().toInstant();
		assertThat(Duration.between(issuedAt, proof.expiresAt()))
				.isEqualTo(Duration.ofMinutes(30));
		assertThat(proof.toString()).contains("[REDACTED]").doesNotContain(proof.token());
		assertNoSecretInStorage(proof.token(), PASSWORD);
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(count("iam_password")).isZero();
		assertThat(actions()).containsExactly("user_created", "account_setup_issued");
	}

	@Test
	void completesAtomicallyWithTheBoundUserAsActorAndCannotBeReplayed() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		UUID correlation = UUID.randomUUID();
		this.setups.complete(user.id(), proof.token(), PASSWORD, SOURCE, correlation);
		assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
		assertThat(this.passwords.matches(PASSWORD, storedPassword(user.id()))).isTrue();
		assertThat(setupStatus()).isEqualTo("consumed");
		assertThat(this.jdbc.sql("SELECT finished_at FROM iam_user_setup").query(OffsetDateTime.class).single()).isNotNull();
		assertThat(actions()).containsExactly("user_created", "account_setup_issued", "initial_password_set", "account_setup_completed");
		var completionEvents = this.jdbc.sql("SELECT actor, source, correlation_id FROM iam_security_audit WHERE action IN ('initial_password_set', 'account_setup_completed')")
				.query().listOfRows();
		assertThat(completionEvents).hasSize(2).allSatisfy(row -> {
			assertThat(row.get("actor")).isEqualTo("user:" + user.id());
			assertThat(row.get("source")).isEqualTo(SOURCE);
			assertThat(row.get("correlation_id")).isEqualTo(correlation);
		});
		assertThatThrownBy(() -> complete(proof, SECOND_PASSWORD)).isInstanceOf(IllegalStateException.class);
		assertThat(this.passwords.matches(PASSWORD, storedPassword(user.id()))).isTrue();
		assertThat(count("iam_security_audit")).isEqualTo(4);
		assertNoSecretInStorage(proof.token(), PASSWORD, storedPassword(user.id()));
	}

	@Test
	void reissuingReplacesThePreviousProof() {
		IdentityUser user = createUser();
		IdentityUserSetup old = this.setups.issue(user.id(), this.audit);
		IdentityUserSetup replacement = this.setups.issue(user.id(), this.audit);
		assertThat(replacement.token()).isNotEqualTo(old.token());
		assertThat(count("iam_user_setup")).isEqualTo(1);
		assertThatIllegalArgumentException().isThrownBy(() -> complete(old, PASSWORD));
		assertPendingWithoutPassword(user);
		complete(replacement, PASSWORD);
		assertThat(count("iam_security_audit")).isEqualTo(5);
	}

	@Test
	void cancelledProofCannotBeConsumedAndCanBeReplaced() {
		IdentityUser user = createUser();
		IdentityUserSetup old = this.setups.issue(user.id(), this.audit);
		this.setups.cancel(user.id(), this.audit);
		assertThat(setupStatus()).isEqualTo("cancelled");
		assertThatIllegalArgumentException().isThrownBy(() -> complete(old, PASSWORD));
		assertThatIllegalStateException().isThrownBy(() -> this.setups.cancel(user.id(), this.audit));
		assertPendingWithoutPassword(user);
		assertThat(actions()).containsExactly("user_created", "account_setup_issued", "account_setup_cancelled");
		complete(this.setups.issue(user.id(), this.audit), PASSWORD);
	}

	@Test
	void refusesCancellationWhenThereIsNoOutstandingProof() {
		IdentityUser user = createUser();
		assertThatIllegalStateException().isThrownBy(() -> this.setups.cancel(user.id(), this.audit));
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		complete(proof, PASSWORD);
		assertThatIllegalStateException().isThrownBy(() -> this.setups.cancel(user.id(), this.audit));
		assertThat(count("iam_security_audit")).isEqualTo(4);
	}

	@Test
	void cancellationWorksForADisabledAccountWithoutReactivatingIt() {
		IdentityUser user = createUser();
		this.setups.issue(user.id(), this.audit);
		this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", user.id()).update();
		this.setups.cancel(user.id(), this.audit);
		assertThat(setupStatus()).isEqualTo("cancelled");
		assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.DISABLED);
	}

	@Test
	void bindsTheProofToItsAccount() {
		IdentityUser first = createUser();
		IdentityUser second = this.users.create("bob", "Bob", this.audit);
		IdentityUserSetup proof = this.setups.issue(first.id(), this.audit);
		this.setups.issue(second.id(), this.audit);
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(second.id(), proof.token(), PASSWORD, SOURCE, UUID.randomUUID()));
		assertPendingWithoutPassword(first);
		assertPendingWithoutPassword(second);
		complete(proof, PASSWORD);
	}

	@Test
	void rejectsUnknownAndMalformedProofsWithoutChangingState() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		for (String token : new String[] { null, "", "invalid", "A".repeat(65_537), this.tokens.generate() }) {
			assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(user.id(), token, PASSWORD, SOURCE, UUID.randomUUID()));
		}
		assertPendingWithoutPassword(user);
		assertThat(setupStatus()).isEqualTo("issued");
		assertThat(count("iam_security_audit")).isEqualTo(2);
		complete(proof, PASSWORD);
	}

	@Test
	void rejectsExpiredProofsAndAllowsReissueOrCancellation() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		expireProof();
		assertThatIllegalArgumentException().isThrownBy(() -> complete(proof, PASSWORD));
		assertPendingWithoutPassword(user);
		assertThat(count("iam_security_audit")).isEqualTo(2);
		this.setups.cancel(user.id(), this.audit);
		complete(this.setups.issue(user.id(), this.audit), PASSWORD);
	}

	@ParameterizedTest
	@ValueSource(strings = { "active", "disabled" })
	void refusesIssuanceAndCompletionForAccountsThatAreNotPending(String state) {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		this.jdbc.sql("UPDATE iam_user SET status = :status WHERE id = :id").param("status", state).param("id", user.id()).update();
		assertThatIllegalStateException().isThrownBy(() -> this.setups.issue(user.id(), this.audit));
		assertThatIllegalStateException().isThrownBy(() -> complete(proof, PASSWORD));
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isEqualTo(2);
	}

	@Test
	void doesNotOverwriteAnExistingInitialPasswordOrActivateALegacyPendingAccount() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		this.users.setInitialPassword(user.id(), PASSWORD, this.audit);
		String original = storedPassword(user.id());
		assertThatIllegalStateException().isThrownBy(() -> this.setups.issue(user.id(), this.audit));
		assertThatIllegalStateException().isThrownBy(() -> complete(proof, SECOND_PASSWORD));
		assertThat(storedPassword(user.id())).isEqualTo(original);
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(setupStatus()).isEqualTo("issued");
		this.setups.cancel(user.id(), this.audit);
	}

	@Test
	void requiresAnExistingUserAndTrustedContextBeforeAnyWrite() {
		UUID missing = UUID.randomUUID();
		assertThatThrownBy(() -> this.setups.issue(missing, this.audit)).isInstanceOf(NoSuchElementException.class);
		assertThatThrownBy(() -> this.setups.cancel(missing, this.audit)).isInstanceOf(NoSuchElementException.class);
		assertThatThrownBy(() -> this.setups.complete(missing, this.tokens.generate(), PASSWORD, SOURCE, UUID.randomUUID()))
				.isInstanceOf(NoSuchElementException.class);
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.issue(null, this.audit));
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.cancel(null, this.audit));
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(null, this.tokens.generate(), PASSWORD, SOURCE, UUID.randomUUID()));
		IdentityUser user = createUser();
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.issue(user.id(), null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.cancel(user.id(), null));
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(user.id(), proof.token(), PASSWORD, null, UUID.randomUUID()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.setups.complete(user.id(), proof.token(), PASSWORD, SOURCE, null));
		assertPendingWithoutPassword(user);
		assertThat(count("iam_security_audit")).isEqualTo(2);
	}

	@Test
	void invalidPasswordsLeaveTheProofUsableForRetry() {
		IdentityUser user = this.users.create("LongAccountName15", "Alice", this.audit);
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		for (String password : new String[] { null, "short", "passwordpassword", "LONGACCOUNTNAME15123!" }) {
			assertThatThrownBy(() -> complete(proof, password)).isInstanceOf(PasswordRejectedException.class);
			assertPendingWithoutPassword(user);
			assertThat(setupStatus()).isEqualTo("issued");
			assertThat(count("iam_security_audit")).isEqualTo(2);
		}
		complete(proof, PASSWORD);
	}

	@ParameterizedTest
	@ValueSource(strings = { "initial_password_set", "account_setup_completed" })
	void auditFailureRollsBackTheEntireCompletionAndAllowsRetry(String action) {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		rejectAudit(action);
		try {
			assertThatThrownBy(() -> complete(proof, PASSWORD)).isInstanceOf(DataIntegrityViolationException.class);
			assertPendingWithoutPassword(user);
			assertThat(setupStatus()).isEqualTo("issued");
			assertThat(count("iam_security_audit")).isEqualTo(2);
		}
		finally {
			allowAudit();
		}
		complete(proof, PASSWORD);
	}

	@Test
	void failedIssuanceOrCancellationPreservesThePreviousProof() {
		IdentityUser user = createUser();
		rejectAudit("account_setup_issued");
		try {
			assertThatThrownBy(() -> this.setups.issue(user.id(), this.audit)).isInstanceOf(DataIntegrityViolationException.class);
			assertThat(count("iam_user_setup")).isZero();
		}
		finally {
			allowAudit();
		}
		IdentityUserSetup original = this.setups.issue(user.id(), this.audit);
		for (String action : new String[] { "account_setup_issued", "account_setup_cancelled" }) {
			rejectAudit(action);
			try {
				if (action.equals("account_setup_issued")) {
					assertThatThrownBy(() -> this.setups.issue(user.id(), this.audit)).isInstanceOf(DataIntegrityViolationException.class);
				}
				else {
					assertThatThrownBy(() -> this.setups.cancel(user.id(), this.audit)).isInstanceOf(DataIntegrityViolationException.class);
				}
				assertThat(this.jdbc.sql("SELECT token_digest FROM iam_user_setup").query(String.class).single())
						.isEqualTo(this.tokens.digest(original.token()));
				assertThat(setupStatus()).isEqualTo("issued");
				assertThat(count("iam_security_audit")).isEqualTo(2);
			}
			finally {
				allowAudit();
			}
		}
		complete(original, PASSWORD);
	}

	@Test
	void outerTransactionRollbackRestoresIssuanceCancellationAndCompletion() {
		IdentityUser user = createUser();
		TransactionTemplate transaction = new TransactionTemplate(this.transactions);
		transaction.executeWithoutResult(status -> {
			this.setups.issue(user.id(), this.audit);
			status.setRollbackOnly();
		});
		assertThat(count("iam_user_setup")).isZero();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		transaction.executeWithoutResult(status -> {
			this.setups.cancel(user.id(), this.audit);
			status.setRollbackOnly();
		});
		assertThat(setupStatus()).isEqualTo("issued");
		transaction.executeWithoutResult(status -> {
			complete(proof, PASSWORD);
			status.setRollbackOnly();
		});
		assertPendingWithoutPassword(user);
		assertThat(setupStatus()).isEqualTo("issued");
		assertThat(count("iam_security_audit")).isEqualTo(2);
		complete(proof, PASSWORD);
	}

	@Test
	void catchingFailureCannotCommitThePartialCompletion() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		rejectAudit("account_setup_completed");
		try {
			assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
				assertThatThrownBy(() -> complete(proof, PASSWORD)).isInstanceOf(DataIntegrityViolationException.class);
			})).isInstanceOf(UnexpectedRollbackException.class);
			assertPendingWithoutPassword(user);
			assertThat(setupStatus()).isEqualTo("issued");
		}
		finally {
			allowAudit();
		}
	}

	@Test
	void rejectsExpiryDuringPasswordStorageAndRollsBackItsAudit() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		this.jdbc.sql("""
				CREATE FUNCTION setup_test_expire() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
				    UPDATE iam_user_setup SET expires_at = clock_timestamp() WHERE user_id = NEW.user_id;
				    RETURN NEW;
				END $$
				""").update();
		try {
			this.jdbc.sql("CREATE TRIGGER setup_test_expire AFTER INSERT ON iam_password FOR EACH ROW EXECUTE FUNCTION setup_test_expire()")
					.update();
			assertThatIllegalArgumentException().isThrownBy(() -> complete(proof, PASSWORD));
			assertPendingWithoutPassword(user);
			assertThat(setupStatus()).isEqualTo("issued");
			assertThat(this.jdbc.sql("SELECT expires_at FROM iam_user_setup").query(OffsetDateTime.class).single().toInstant())
					.isEqualTo(proof.expiresAt());
			assertThat(count("iam_security_audit")).isEqualTo(2);
		}
		finally {
			this.jdbc.sql("DROP TRIGGER IF EXISTS setup_test_expire ON iam_password").update();
			this.jdbc.sql("DROP FUNCTION setup_test_expire()").update();
		}
		complete(proof, PASSWORD);
	}

	@Test
	void silentlySuppressedActivationRollsBackThePasswordAndConsumption() {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		this.jdbc.sql("CREATE FUNCTION setup_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER setup_test_suppress BEFORE UPDATE ON iam_user FOR EACH ROW EXECUTE FUNCTION setup_test_suppress()")
					.update();
			assertThatIllegalStateException().isThrownBy(() -> complete(proof, PASSWORD));
			assertPendingWithoutPassword(user);
			assertThat(setupStatus()).isEqualTo("issued");
			assertThat(count("iam_security_audit")).isEqualTo(2);
		}
		finally {
			this.jdbc.sql("DROP TRIGGER IF EXISTS setup_test_suppress ON iam_user").update();
			this.jdbc.sql("DROP FUNCTION setup_test_suppress()").update();
		}
		complete(proof, PASSWORD);
	}

	@Test
	void workflowOnlyUserOperationsRejectCallsWithoutAnExistingTransaction() {
		IdentityUser user = createUser();
		assertThatThrownBy(() -> this.users.lockById(user.id())).isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.users.lockForSetup(user.id())).isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.users.activateAfterSetup(user.id())).isInstanceOf(IllegalTransactionStateException.class);
		assertPendingWithoutPassword(user);
	}

	@Test
	void twoConcurrentConsumersHaveExactlyOneWinner() throws Exception {
		IdentityUserSetup proof = this.setups.issue(createUser().id(), this.audit);
		List<Boolean> result = race(() -> { complete(proof, PASSWORD); return true; },
				() -> { complete(proof, SECOND_PASSWORD); return true; });
		assertThat(result).containsExactlyInAnyOrder(true, false);
		assertThat(this.passwords.matches(PASSWORD, storedPassword(proof.userId()))).isEqualTo(result.get(0));
		assertThat(this.passwords.matches(SECOND_PASSWORD, storedPassword(proof.userId()))).isEqualTo(result.get(1));
		assertThat(count("iam_password")).isEqualTo(1);
		assertThat(count("iam_security_audit")).isEqualTo(4);
	}

	@Test
	void cancellationAndConsumptionSerializeWithoutPartialState() throws Exception {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		List<Boolean> result = race(() -> { this.setups.cancel(user.id(), this.audit); return true; },
				() -> { complete(proof, PASSWORD); return true; });
		assertThat(result).containsExactlyInAnyOrder(true, false);
		if (result.get(0)) {
			assertThat(setupStatus()).isEqualTo("cancelled");
			assertPendingWithoutPassword(user);
			assertThat(count("iam_security_audit")).isEqualTo(3);
		}
		else {
			assertThat(setupStatus()).isEqualTo("consumed");
			assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(count("iam_security_audit")).isEqualTo(4);
		}
	}

	@Test
	void concurrentIssuanceLeavesOnlyTheLastSerializedProofUsable() throws Exception {
		IdentityUser user = createUser();
		try (var executor = Executors.newFixedThreadPool(2)) {
			CountDownLatch start = new CountDownLatch(1);
			Callable<IdentityUserSetup> issue = () -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				return this.setups.issue(user.id(), this.audit);
			};
			var first = executor.submit(issue);
			var second = executor.submit(issue);
			start.countDown();
			IdentityUserSetup a = first.get(20, TimeUnit.SECONDS);
			IdentityUserSetup b = second.get(20, TimeUnit.SECONDS);
			assertThat(a.token()).isNotEqualTo(b.token());
			String digest = this.jdbc.sql("SELECT token_digest FROM iam_user_setup").query(String.class).single();
			IdentityUserSetup current = digest.equals(this.tokens.digest(a.token())) ? a : b;
			IdentityUserSetup replaced = current == a ? b : a;
			assertThatIllegalArgumentException().isThrownBy(() -> complete(replaced, PASSWORD));
			complete(current, PASSWORD);
			assertThat(count("iam_user_setup")).isEqualTo(1);
			assertThat(count("iam_security_audit")).isEqualTo(5);
		}
	}

	@Test
	void reissueAndConsumptionSerializeWithoutRevivingTheOldProof() throws Exception {
		IdentityUser user = createUser();
		IdentityUserSetup old = this.setups.issue(user.id(), this.audit);
		var replacement = new java.util.concurrent.atomic.AtomicReference<IdentityUserSetup>();
		List<Boolean> result = race(() -> {
			replacement.set(this.setups.issue(user.id(), this.audit)); return true;
		}, () -> { complete(old, PASSWORD); return true; });
		assertThat(result).containsExactlyInAnyOrder(true, false);
		if (result.get(0)) {
			assertPendingWithoutPassword(user);
			assertThatIllegalArgumentException().isThrownBy(() -> complete(old, PASSWORD));
			complete(replacement.get(), PASSWORD);
		}
		else {
			assertThat(replacement.get()).isNull();
			assertThat(setupStatus()).isEqualTo("consumed");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "expire", "disable", "cancel", "replace" })
	void rechecksProofAndAccountAfterWaitingForTheUserLock(String change) throws Exception {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		try (var blocker = this.dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try (var statement = blocker.prepareStatement("SELECT id FROM iam_user WHERE id = ? FOR UPDATE")) {
				statement.setObject(1, user.id());
				try (var result = statement.executeQuery()) { assertThat(result.next()).isTrue(); }
			}
			var waiting = executor.submit(() -> complete(proof, PASSWORD));
			try {
				await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(this.jdbc.sql("""
						SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
						AND wait_event_type = 'Lock' AND query LIKE '%FROM iam_user WHERE id = %FOR UPDATE%'
						""").query(Long.class).single()).isEqualTo(1));
				String sql = switch (change) {
					case "expire" -> "UPDATE iam_user_setup SET expires_at = clock_timestamp() WHERE user_id = ?";
					case "disable" -> "UPDATE iam_user SET status = 'disabled' WHERE id = ?";
					case "cancel" -> "UPDATE iam_user_setup SET status = 'cancelled', finished_at = clock_timestamp() WHERE user_id = ?";
					default -> "UPDATE iam_user_setup SET token_digest = repeat('0', 64) WHERE user_id = ?";
				};
				try (var statement = blocker.prepareStatement(sql)) {
					statement.setObject(1, user.id()); statement.executeUpdate();
				}
				blocker.commit();
				assertThatThrownBy(() -> waiting.get(20, TimeUnit.SECONDS))
						.hasCauseInstanceOf(change.equals("disable") ? IllegalStateException.class : IllegalArgumentException.class);
			}
			finally {
				blocker.rollback();
			}
		}
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isEqualTo(2);
	}

	@Test
	void anInitialPasswordWriteAndCompletionCannotOverwriteEachOther() throws Exception {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		List<Boolean> result = race(() -> {
			this.users.setInitialPassword(user.id(), SECOND_PASSWORD, this.audit); return true;
		}, () -> { complete(proof, PASSWORD); return true; });
		assertThat(result).containsExactlyInAnyOrder(true, false);
		assertThat(count("iam_password")).isEqualTo(1);
		if (result.get(0)) {
			assertThat(this.users.findById(user.id())).contains(user);
			assertThat(this.passwords.matches(SECOND_PASSWORD, storedPassword(user.id()))).isTrue();
			assertThat(setupStatus()).isEqualTo("issued");
			assertThat(count("iam_security_audit")).isEqualTo(3);
		}
		else {
			assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
			assertThat(this.passwords.matches(PASSWORD, storedPassword(user.id()))).isTrue();
			assertThat(setupStatus()).isEqualTo("consumed");
			assertThat(count("iam_security_audit")).isEqualTo(4);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"token_digest = 'plaintext-secret'", "token_digest = repeat('A', 64)",
			"token_digest = repeat('a', 65)", "token_digest = NULL", "status = 'unknown'",
			"expires_at = issued_at", "expires_at = issued_at - INTERVAL '1 second'",
			"issued_at = '-infinity'", "expires_at = 'infinity'",
			"finished_at = clock_timestamp()", "status = 'consumed'", "status = 'cancelled'",
			"status = 'consumed', finished_at = issued_at - INTERVAL '1 second'",
			"status = 'cancelled', finished_at = 'infinity'"
	})
	void databaseRejectsInvalidProofData(String assignment) {
		IdentityUserSetup proof = this.setups.issue(createUser().id(), this.audit);
		// Fixed SQL fragments supplied only by this test's annotation.
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user_setup SET " + assignment).update())
				.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(setupStatus()).isEqualTo("issued");
		assertThat(count("iam_security_audit")).isEqualTo(2);
		complete(proof, PASSWORD);
	}

	@Test
	void databaseBindsProofsToExistingUsersAndPreventsDigestReuseAcrossAccounts() {
		IdentityUser first = createUser();
		IdentityUser second = this.users.create("bob", "Bob", this.audit);
		IdentityUserSetup proof = this.setups.issue(first.id(), this.audit);
		this.setups.issue(second.id(), this.audit);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user_setup SET user_id = :id WHERE user_id = :first")
				.param("id", UUID.randomUUID()).param("first", first.id()).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user_setup SET token_digest = :digest WHERE user_id = :second")
				.param("digest", this.tokens.digest(proof.token())).param("second", second.id()).update())
				.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_user WHERE id = :id").param("id", first.id()).update())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "cancel", "consume", "audit" })
	void silentlySuppressedWritesFailAndPreserveTheOriginalProof(String operation) {
		IdentityUser user = createUser();
		IdentityUserSetup proof = this.setups.issue(user.id(), this.audit);
		String table = operation.equals("audit") ? "iam_security_audit" : "iam_user_setup";
		String mutation = operation.equals("audit") ? "INSERT" : "UPDATE";
		this.jdbc.sql("CREATE FUNCTION setup_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER setup_test_suppress BEFORE " + mutation + " ON " + table
					+ " FOR EACH ROW EXECUTE FUNCTION setup_test_suppress()").update();
			assertThatThrownBy(() -> {
				switch (operation) {
					case "issue" -> this.setups.issue(user.id(), this.audit);
					case "cancel" -> this.setups.cancel(user.id(), this.audit);
					default -> complete(proof, PASSWORD);
				}
			}).isInstanceOf(RuntimeException.class);
			assertPendingWithoutPassword(user);
			assertThat(setupStatus()).isEqualTo("issued");
			assertThat(this.jdbc.sql("SELECT token_digest FROM iam_user_setup").query(String.class).single())
					.isEqualTo(this.tokens.digest(proof.token()));
			assertThat(count("iam_security_audit")).isEqualTo(2);
		}
		finally {
			this.jdbc.sql("DROP TRIGGER IF EXISTS setup_test_suppress ON " + table).update();
			this.jdbc.sql("DROP FUNCTION setup_test_suppress()").update();
		}
		complete(proof, PASSWORD);
	}

	@Test
	void newApplicationInstanceCanConsumeAPersistedProof() {
		IdentityUserSetup proof = this.setups.issue(createUser().id(), this.audit);
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE)
				.properties(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(),
						"spring.datasource.username", this.postgres.getUsername(),
						"spring.datasource.password", this.postgres.getPassword(), "spring.main.banner-mode", "off"))
				.run()) {
			restarted.getBean(IdentityUserSetups.class).complete(proof.userId(), proof.token(), PASSWORD, SOURCE, UUID.randomUUID());
		}
		assertThat(this.users.findById(proof.userId()).orElseThrow().status()).isEqualTo(IdentityUser.Status.ACTIVE);
		assertThat(this.jdbc.sql("SELECT count(*) FROM flyway_schema_history WHERE success AND version IN ('1', '2', '3')")
				.query(Long.class).single()).isEqualTo(3);
	}

	@Test
	void upgradesV2WithoutChangingExistingIdentityCredentialOrAuditData() throws Exception {
		String schema = "setup_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
					.schemas(schema).defaultSchema(schema).target("2").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				JdbcClient previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID id = UUID.randomUUID();
				String hash = this.passwords.hash(PASSWORD, "alice");
				previous.sql("INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'alice', 'Alice')").param("id", id).update();
				previous.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)").param("id", id).param("hash", hash).update();
				previous.sql("""
						INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
						VALUES (:eventId, 'system:upgrade-test', 'internal:upgrade-test', :correlation, :userId, 'user_created', 'success')
						""").param("eventId", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("userId", id).update();
				var beforeUser = previous.sql("SELECT row_to_json(u)::text FROM iam_user u").query(String.class).single();
				var beforeAudit = previous.sql("SELECT row_to_json(a)::text FROM iam_security_audit a").query(String.class).single();
				Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
						.schemas(schema).defaultSchema(schema).load().migrate();
				assertThat(previous.sql("SELECT row_to_json(u)::text FROM iam_user u").query(String.class).single()).isEqualTo(beforeUser);
				assertThat(previous.sql("SELECT row_to_json(a)::text FROM iam_security_audit a").query(String.class).single()).isEqualTo(beforeAudit);
				assertThat(previous.sql("SELECT password_hash FROM iam_password").query(String.class).single()).isEqualTo(hash);
				assertThat(previous.sql("SELECT count(*) FROM iam_user_setup").query(Long.class).single()).isZero();
				assertThat(previous.sql("SELECT count(*) FROM flyway_schema_history WHERE version IN ('1', '2', '3') AND success")
						.query(Long.class).single()).isEqualTo(3);
			}
		}
		finally {
			this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update();
		}
	}

	private IdentityUser createUser() {
		return this.users.create("alice", "Alice", this.audit);
	}

	private void complete(IdentityUserSetup proof, String password) {
		this.setups.complete(proof.userId(), proof.token(), password, SOURCE, UUID.randomUUID());
	}

	private void assertPendingWithoutPassword(IdentityUser user) {
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password WHERE user_id = :id").param("id", user.id()).query(Long.class).single()).isZero();
	}

	private String storedPassword(UUID id) {
		return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", id).query(String.class).single();
	}

	private String setupStatus() {
		return this.jdbc.sql("SELECT status FROM iam_user_setup").query(String.class).single();
	}

	private List<String> actions() {
		return this.jdbc.sql("SELECT action FROM iam_security_audit ORDER BY recorded_at, id").query(String.class).list();
	}

	private long count(String table) {
		return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
	}

	private void assertNoSecretInStorage(String... secrets) {
		assertThat(this.jdbc.sql("SELECT row_to_json(s)::text FROM iam_user_setup s").query(String.class).list())
				.allSatisfy(row -> assertThat(row).doesNotContain(secrets));
		assertThat(this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a").query(String.class).list())
				.allSatisfy(row -> assertThat(row).doesNotContain(secrets));
	}

	private void expireProof() {
		this.jdbc.sql("UPDATE iam_user_setup SET expires_at = clock_timestamp()").update();
	}

	private void rejectAudit(String action) {
		assertThat(action).isIn("account_setup_issued", "account_setup_cancelled", "initial_password_set", "account_setup_completed");
		// PostgreSQL DDL does not support bind parameters; values above are a fixed test-only allowlist.
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT setup_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
	}

	private void allowAudit() {
		this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT setup_test_reject").update();
	}

	private List<Boolean> race(Callable<Boolean> first, Callable<Boolean> second) throws Exception {
		try (var executor = Executors.newFixedThreadPool(2)) {
			CountDownLatch start = new CountDownLatch(1);
			var a = executor.submit(() -> raceResult(first, start));
			var b = executor.submit(() -> raceResult(second, start));
			start.countDown();
			return List.of(a.get(20, TimeUnit.SECONDS), b.get(20, TimeUnit.SECONDS));
		}
	}

	private boolean raceResult(Callable<Boolean> operation, CountDownLatch start) throws Exception {
		assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
		try {
			return operation.call();
		}
		catch (IllegalStateException | IllegalArgumentException ex) {
			return false;
		}
	}

}
