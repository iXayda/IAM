package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserStatesIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:state-test", "internal:test", UUID.randomUUID());
	private static final List<String> TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_security_audit");

	@Autowired
	private IdentityUserStates states;
	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private IdentityPasswordRecoveries recoveries;
	@Autowired
	private IdentityProfiles profiles;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private PlatformTransactionManager transactions;
	@Autowired
	private PostgreSQLContainer postgres;

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void disablingAnActiveUserRevokesOnlyItsSessionsAndProofAndPreservesIdentityAndPassword() {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		var proof = this.recoveries.issue(alice.id(), SYSTEM);
		var otherProof = this.recoveries.issue(bob.id(), SYSTEM);
		session(alice.id()); session(alice.id());
		String otherSession = session(bob.id());
		String identity = this.jdbc.sql("SELECT (to_jsonb(u) - 'status')::text FROM iam_user u WHERE id = :id")
				.param("id", alice.id()).query(String.class).single();
		String password = this.jdbc.sql("SELECT (to_jsonb(p) - 'credential_version')::text FROM iam_password p WHERE user_id = :id")
				.param("id", alice.id()).query(String.class).single();
		var audit = new SecurityAuditContext("system:operator", "internal:accounts", UUID.randomUUID());
		assertThat(this.states.disable(alice.id(), audit)).isEqualTo(IdentityUserStates.Result.CHANGED);
		assertThat(status(alice.id())).isEqualTo(IdentityUser.Status.DISABLED);
		assertThat(version(alice.id())).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT (to_jsonb(u) - 'status')::text FROM iam_user u WHERE id = :id")
				.param("id", alice.id()).query(String.class).single()).isEqualTo(identity);
		assertThat(this.jdbc.sql("SELECT (to_jsonb(p) - 'credential_version')::text FROM iam_password p WHERE user_id = :id")
				.param("id", alice.id()).query(String.class).single()).isEqualTo(password);
		assertThat(this.jdbc.sql("SELECT session_id FROM iam_browser_session").query(String.class).list()).containsExactly(otherSession);
		assertThat(this.users.findById(bob.id())).contains(bob);
		assertThat(version(bob.id())).isEqualTo(1);
		assertThat(proofStatus(alice.id(), "iam_password_recovery")).isEqualTo("cancelled");
		var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE correlation_id = :id")
				.param("id", audit.correlationId()).query().listOfRows();
		assertThat(events).hasSize(3).allSatisfy(event -> {
			assertThat(event.get("actor")).isEqualTo(audit.actor());
			assertThat(event.get("source")).isEqualTo(audit.source());
			assertThat(event.get("target_user_id")).isEqualTo(alice.id());
			assertThat(event.get("outcome")).isEqualTo("success");
		});
		assertThat(events.stream().map(event -> event.get("action")).toList())
				.containsExactlyInAnyOrder("password_recovery_cancelled", "browser_sessions_revoked", "user_disabled");
		assertThat(this.states.enable(alice.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
		assertThat(status(alice.id())).isEqualTo(IdentityUser.Status.ACTIVE);
		assertThat(version(alice.id())).isEqualTo(2);
		assertThat(this.recoveries.complete(alice.id(), proof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID()))
				.isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
		assertThat(this.recoveries.complete(bob.id(), otherProof.token(), NEW_PASSWORD, "internal:test", UUID.randomUUID()))
				.isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
		assertThatThrownBy(() -> this.users.create("ALICE", "Duplicate", SYSTEM)).isInstanceOf(DataIntegrityViolationException.class);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void reEnablingAnUnopenedUserRequiresSetupEvenIfItAlreadyHasAnInitialPassword(boolean initialPassword) {
		var user = this.users.create("alice", "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		if (initialPassword) { this.users.setInitialPassword(user.id(), PASSWORD, SYSTEM); }
		assertThat(this.states.disable(user.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
		assertThat(proofStatus(user.id(), "iam_user_setup")).isEqualTo("cancelled");
		assertThat(this.states.enable(user.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.CHANGED);
		assertThat(status(user.id())).isEqualTo(IdentityUser.Status.PENDING);
		assertThatThrownBy(() -> this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID()))
				.isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class);
		if (!initialPassword) {
			var replacement = this.setups.issue(user.id(), SYSTEM);
			this.setups.complete(user.id(), replacement.token(), PASSWORD, "internal:test", UUID.randomUUID());
			assertThat(status(user.id())).isEqualTo(IdentityUser.Status.ACTIVE);
		}
		else { assertThat(version(user.id())).isEqualTo(2); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing-proof", "missing-password" })
	void reEnablingCannotGrantActiveStatusWithoutBothSetupEvidenceAndAPassword(String missing) {
		var user = activeUser("alice");
		this.states.disable(user.id(), SYSTEM);
		this.jdbc.sql("DELETE FROM " + (missing.equals("missing-proof") ? "iam_user_setup" : "iam_password")).update();
		this.states.enable(user.id(), SYSTEM);
		assertThat(status(user.id())).isEqualTo(IdentityUser.Status.PENDING);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void repeatedOperationsNeitherChangeVersionsNorAppendEvents(boolean active) {
		var user = active ? activeUser("alice") : this.users.create("alice", "Alice", SYSTEM);
		var original = snapshot();
		assertThat(this.states.enable(user.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.UNCHANGED);
		assertThat(snapshot()).isEqualTo(original);
		this.states.disable(user.id(), SYSTEM);
		var disabled = snapshot();
		assertThat(this.states.disable(user.id(), SYSTEM)).isEqualTo(IdentityUserStates.Result.UNCHANGED);
		assertThat(snapshot()).isEqualTo(disabled);
		this.states.enable(user.id(), SYSTEM);
		assertThat(status(user.id())).isEqualTo(active ? IdentityUser.Status.ACTIVE : IdentityUser.Status.PENDING);
		this.states.disable(user.id(), SYSTEM);
		if (active) { assertThat(version(user.id())).isEqualTo(3); }
	}

	@Test
	void missingIdentityOrAuditContextIsRejectedWithoutAnyWrites() {
		var user = activeUser("alice");
		var before = snapshot();
		assertThatThrownBy(() -> this.states.disable(UUID.randomUUID(), SYSTEM)).isInstanceOf(NoSuchElementException.class);
		assertThatThrownBy(() -> this.states.enable(UUID.randomUUID(), SYSTEM)).isInstanceOf(NoSuchElementException.class);
		assertThatIllegalArgumentException().isThrownBy(() -> this.states.disable(null, SYSTEM));
		assertThatIllegalArgumentException().isThrownBy(() -> this.states.enable(null, SYSTEM));
		assertThatIllegalArgumentException().isThrownBy(() -> this.states.disable(user.id(), null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.states.enable(user.id(), null));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void outerRollbackRestoresTheStateProofsVersionsSessionsAndAuditTogether() {
		var user = activeUser("alice");
		this.recoveries.issue(user.id(), SYSTEM);
		session(user.id());
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			this.states.disable(user.id(), SYSTEM);
			assertThat(status(user.id())).isEqualTo(IdentityUser.Status.DISABLED);
			tx.setRollbackOnly();
		});
		assertThat(snapshot()).isEqualTo(before);
		this.states.disable(user.id(), SYSTEM);
		var disabled = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			this.states.enable(user.id(), SYSTEM);
			tx.setRollbackOnly();
		});
		assertThat(snapshot()).isEqualTo(disabled);
	}

	@ParameterizedTest
	@ValueSource(strings = { "state-error", "state-skipped", "state-retained", "version-skipped", "version-retained", "version-overflow",
			"setup-skipped", "setup-retained", "recovery-skipped", "recovery-retained", "sessions-skipped",
			"audit-error", "audit-skipped", "audit-deferred", "cancellation-audit", "revocation-audit" })
	void disablingFaultsRollBackEveryPartOfTheWorkflow(String fault) {
		boolean pending = fault.startsWith("setup");
		var user = pending ? this.users.create("alice", "Alice", SYSTEM) : activeUser("alice");
		if (pending) { this.setups.issue(user.id(), SYSTEM); }
		else { this.recoveries.issue(user.id(), SYSTEM); session(user.id()); }
		if (fault.equals("version-overflow")) {
			this.jdbc.sql("UPDATE iam_password SET credential_version = :version").param("version", Long.MAX_VALUE).update();
		}
		var before = snapshot();
		String table = fault.equals("version-overflow") ? null : installFault(fault, "user_disabled");
		try {
			assertThatThrownBy(() -> this.states.disable(user.id(), SYSTEM)).isInstanceOf(RuntimeException.class);
			assertThat(snapshot()).isEqualTo(before);
		}
		finally { if (table != null) { removeFault(table); } }
	}

	@ParameterizedTest
	@ValueSource(strings = { "state-skipped", "state-retained", "audit-skipped", "audit-deferred" })
	void enablingFaultsLeaveTheUserDisabledAndNeverRestoreRevokedState(String fault) {
		var user = activeUser("alice");
		this.recoveries.issue(user.id(), SYSTEM);
		session(user.id());
		this.states.disable(user.id(), SYSTEM);
		var before = snapshot();
		String table = installFault(fault, "user_enabled");
		try {
			assertThatThrownBy(() -> this.states.enable(user.id(), SYSTEM)).isInstanceOf(RuntimeException.class);
			assertThat(snapshot()).isEqualTo(before);
		}
		finally { removeFault(table); }
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void concurrentIdenticalOperationsProduceOneChangeAndOneEvent(boolean enabling) throws Exception {
		var user = activeUser("alice");
		if (enabling) { this.states.disable(user.id(), SYSTEM); }
		var start = new CountDownLatch(1);
		Callable<IdentityUserStates.Result> operation = () -> {
			assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
			return enabling ? this.states.enable(user.id(), SYSTEM) : this.states.disable(user.id(), SYSTEM);
		};
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(operation);
			var second = executor.submit(operation);
			start.countDown();
			assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
					.containsExactlyInAnyOrder(IdentityUserStates.Result.CHANGED, IdentityUserStates.Result.UNCHANGED);
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action")
				.param("action", enabling ? "user_enabled" : "user_disabled").query(Long.class).single()).isEqualTo(1);
		assertThat(version(user.id())).isEqualTo(2);
	}

	@ParameterizedTest
	@ValueSource(strings = { "setup", "recovery", "profile", "recovery-issue", "setup-issue" })
	void workflowsWaitingForTheUserLockRecheckDisableEvenAfterReEnabling(String operation) throws Exception {
		boolean pending = operation.startsWith("setup");
		var user = pending ? this.users.create("alice", "Alice", SYSTEM) : activeUser("alice");
		String token = pending ? this.setups.issue(user.id(), SYSTEM).token() : this.recoveries.issue(user.id(), SYSTEM).token();
		String session = session(user.id());
		try (var executor = Executors.newSingleThreadExecutor()) {
			var waiting = new TransactionTemplate(this.transactions).execute(tx -> {
				this.users.lockById(user.id());
				int pid = this.jdbc.sql("SELECT pg_backend_pid()").query(Integer.class).single();
				var future = executor.submit(() -> {
					switch (operation) {
						case "setup" -> assertThatThrownBy(() -> this.setups.complete(user.id(), token, PASSWORD, "internal:test", UUID.randomUUID()))
								.isInstanceOf(IllegalArgumentException.class);
						case "recovery" -> assertThat(this.recoveries.complete(user.id(), token, NEW_PASSWORD, "internal:test", UUID.randomUUID()))
								.isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
						case "profile" -> assertThat(this.profiles.updateDisplayName(user.id(), session, 1, System.currentTimeMillis(), "Changed", UUID.randomUUID()))
								.isEqualTo(IdentityProfiles.Result.INVALID_SESSION);
						case "recovery-issue" -> assertThatIllegalStateException().isThrownBy(() -> this.recoveries.issue(user.id(), SYSTEM));
						case "setup-issue" -> assertThatIllegalStateException().isThrownBy(() -> this.setups.issue(user.id(), SYSTEM));
						default -> throw new AssertionError(operation);
					}
				});
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql(
						"SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
						.param("pid", pid).query(Boolean.class).single());
				this.states.disable(user.id(), SYSTEM);
				if (!operation.endsWith("issue")) { this.states.enable(user.id(), SYSTEM); }
				return future;
			});
			waiting.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.users.findById(user.id()).orElseThrow().displayName()).isEqualTo("Alice");
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
	}

	@Test
	void disablingWaitsForAConcurrentSetupAndThenRevokesTheNewlyActivatedAccount() throws Exception {
		var user = this.users.create("alice", "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var waiting = new TransactionTemplate(this.transactions).execute(tx -> {
				this.users.lockById(user.id());
				int pid = this.jdbc.sql("SELECT pg_backend_pid()").query(Integer.class).single();
				var future = executor.submit(() -> this.states.disable(user.id(), SYSTEM));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql(
						"SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
						.param("pid", pid).query(Boolean.class).single());
				this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
				return future;
			});
			assertThat(waiting.get(10, TimeUnit.SECONDS)).isEqualTo(IdentityUserStates.Result.CHANGED);
		}
		assertThat(status(user.id())).isEqualTo(IdentityUser.Status.DISABLED);
		assertThat(version(user.id())).isEqualTo(2);
		assertThat(proofStatus(user.id(), "iam_user_setup")).isEqualTo("consumed");
		this.states.enable(user.id(), SYSTEM);
		assertThat(status(user.id())).isEqualTo(IdentityUser.Status.ACTIVE);
	}

	@Test
	void upgradingV8PreservesEveryRowAndExtendsOnlyAuditConstraints() throws Exception {
		var user = activeUser("alice");
		this.recoveries.issue(user.id(), SYSTEM);
		session(user.id());
		String schema = "state_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "8").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : TABLES) { previous.sql("INSERT INTO " + table + " SELECT * FROM public." + table).update(); }
				for (Action action : EnumSet.range(Action.USER_CREATED, Action.USER_PROFILE_UPDATED)) {
					insertEvent(previous, user.id(), action);
				}
				var before = snapshot(previous);
				flyway(schema, "9").migrate();
				assertThat(snapshot(previous)).isEqualTo(before);
				for (Action action : List.of(Action.USER_DISABLED, Action.USER_ENABLED)) {
					insertEvent(previous, user.id(), action);
					String name = action.name().toLowerCase(Locale.ROOT);
					assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET outcome = 'failure' WHERE action = :action")
							.param("action", name).update()).isInstanceOf(DataIntegrityViolationException.class);
					assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET target_user_id = NULL WHERE action = :action")
							.param("action", name).update()).isInstanceOf(DataIntegrityViolationException.class);
				}
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET action = 'unknown_action'").update())
						.isInstanceOf(DataIntegrityViolationException.class);
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private void insertEvent(JdbcClient client, UUID userId, Action action) {
		client.sql("""
				INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
				VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, :action, :outcome)
				""").param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", userId)
				.param("action", action.name().toLowerCase(Locale.ROOT)).param("outcome", action.isFailure() ? "failure" : "success").update();
	}

	private IdentityUser activeUser(String name) {
		var user = this.users.create(name, "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
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

	private IdentityUser.Status status(UUID userId) { return this.users.findById(userId).orElseThrow().status(); }

	private long version(UUID userId) {
		return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", userId).query(Long.class).single();
	}

	private String proofStatus(UUID userId, String table) {
		return this.jdbc.sql("SELECT status FROM " + table + " WHERE user_id = :id").param("id", userId).query(String.class).single();
	}

	private List<List<String>> snapshot() { return snapshot(this.jdbc); }

	private List<List<String>> snapshot(JdbcClient client) {
		return TABLES.stream().map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

	private String installFault(String fault, String stateAction) {
		String table;
		String operation = "UPDATE";
		String body;
		if (fault.startsWith("state")) {
			table = "iam_user";
			body = fault.endsWith("skipped") ? "RETURN NULL;" : fault.endsWith("retained")
					? "NEW.status := OLD.status; RETURN NEW;" : "RAISE EXCEPTION 'injected state storage failure';";
		}
		else if (fault.startsWith("version")) {
			table = "iam_password";
			body = fault.endsWith("skipped") ? "RETURN NULL;" : "NEW.credential_version := OLD.credential_version; RETURN NEW;";
		}
		else if (fault.startsWith("setup") || fault.startsWith("recovery")) {
			table = fault.startsWith("setup") ? "iam_user_setup" : "iam_password_recovery";
			body = fault.endsWith("skipped") ? "RETURN NULL;" : "RETURN OLD;";
		}
		else if (fault.startsWith("sessions")) {
			table = "iam_browser_session"; operation = "DELETE"; body = "RETURN NULL;";
		}
		else {
			table = "iam_security_audit"; operation = "INSERT";
			String action = fault.equals("cancellation-audit") ? "password_recovery_cancelled"
					: fault.equals("revocation-audit") ? "browser_sessions_revoked" : stateAction;
			body = "IF NEW.action <> '" + action + "' THEN RETURN NEW; END IF; "
					+ (fault.endsWith("skipped") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected state audit failure';");
		}
		this.jdbc.sql("CREATE FUNCTION state_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		String trigger = fault.endsWith("deferred") ? "CREATE CONSTRAINT TRIGGER state_test_fault AFTER INSERT ON " + table
				+ " DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER state_test_fault BEFORE " + operation + " ON " + table;
		this.jdbc.sql(trigger + " FOR EACH ROW EXECUTE FUNCTION state_test_fault()").update();
		return table;
	}

	private void removeFault(String table) {
		this.jdbc.sql("DROP TRIGGER IF EXISTS state_test_fault ON " + table).update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS state_test_fault()").update();
	}

}
