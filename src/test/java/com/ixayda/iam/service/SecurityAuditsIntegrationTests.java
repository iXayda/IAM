package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@Import(PostgreSqlTestConfiguration.class)
class SecurityAuditsIntegrationTests {

	private final SecurityAuditContext audit = new SecurityAuditContext("system:integration-test", "integration-test", UUID.randomUUID());

	@Autowired
	private IdentityUsers users;

	@Autowired
	private SecurityAudits audits;

	@Autowired
	private JdbcClient jdbc;

	@Autowired
	private PasswordHasher passwords;

	@Autowired
	private PostgreSQLContainer postgres;

	@Autowired
	private PlatformTransactionManager transactions;

	@BeforeEach
	void removeTestData() {
		this.jdbc.sql("DELETE FROM iam_security_audit").update();
		this.jdbc.sql("DELETE FROM iam_user_setup").update();
		this.jdbc.sql("DELETE FROM iam_password").update();
		this.jdbc.sql("DELETE FROM iam_user").update();
	}

	@Test
	void recordsSuccessfulWritesWithExplicitAttributionWithoutCredentialOrProfileData() {
		Instant before = Instant.now();
		IdentityUser user = this.users.create("alice", "Private Display Name", this.audit);
		SecurityAuditContext enrollment = new SecurityAuditContext("system:enrollment", "internal:enrollment", this.audit.correlationId());
		String password = "seven amber lanterns by the river";
		this.users.setInitialPassword(user.id(), password, enrollment);
		var events = this.jdbc.sql("SELECT * FROM iam_security_audit ORDER BY recorded_at, id").query().listOfRows();
		assertThat(events).hasSize(2);
		assertThat(events).extracting(row -> row.get("action")).containsExactly("user_created", "initial_password_set");
		assertThat(events).extracting(row -> row.get("id")).doesNotHaveDuplicates().doesNotContainNull();
		assertThat(events).extracting(row -> row.get("actor")).containsExactly(this.audit.actor(), enrollment.actor());
		assertThat(events).extracting(row -> row.get("source")).containsExactly(this.audit.source(), enrollment.source());
		for (var event : events) {
			assertThat(event.get("target_user_id")).isEqualTo(user.id());
			assertThat(event.get("correlation_id")).isEqualTo(this.audit.correlationId());
			assertThat(event.get("outcome")).isEqualTo("success");
		}
		assertThat(this.jdbc.sql("SELECT recorded_at FROM iam_security_audit")
				.query((row, index) -> row.getObject("recorded_at", OffsetDateTime.class).toInstant()).list())
				.allSatisfy(time -> assertThat(time).isBetween(before, Instant.now()));
		String hash = this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id")
				.param("id", user.id()).query(String.class).single();
		assertThat(this.jdbc.sql("SELECT row_to_json(audit_row)::text FROM iam_security_audit audit_row")
				.query(String.class).list()).allSatisfy(json -> assertThat(json)
						.doesNotContain(password, hash, user.username(), user.displayName()));
	}

	@Test
	void rollsBackUserCreationWhenAuditStorageRejectsTheEvent() {
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT audit_test_reject CHECK (action <> 'user_created')").update();
		try {
			assertThatThrownBy(() -> this.users.create("alice", "Alice", this.audit)).isInstanceOf(DataIntegrityViolationException.class);
			assertThat(this.users.findByUsername("alice")).isEmpty();
			assertThat(auditCount()).isZero();
		}
		finally {
			this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT audit_test_reject").update();
		}
	}

	@Test
	void rollsBackInitialPasswordWhenAuditStorageRejectsTheEventAndAllowsRetry() {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT audit_test_reject CHECK (action <> 'initial_password_set')").update();
		try {
			assertThatThrownBy(() -> this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit))
					.isInstanceOf(DataIntegrityViolationException.class);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password").query(Long.class).single()).isZero();
			assertThat(this.users.findById(user.id())).contains(user);
			assertThat(auditCount()).isEqualTo(1);
		}
		finally {
			this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT audit_test_reject").update();
		}
		this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit);
		assertThat(auditCount()).isEqualTo(2);
	}

	@Test
	void rollsBackBusinessWritesWhenAuditInsertIsSilentlySuppressed() {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		this.jdbc.sql("""
				CREATE FUNCTION audit_test_suppress_insert() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RETURN NULL; END $$
				""").update();
		try {
			this.jdbc.sql("""
					CREATE TRIGGER audit_test_suppress BEFORE INSERT ON iam_security_audit
					FOR EACH ROW EXECUTE FUNCTION audit_test_suppress_insert()
					""").update();
			assertThatIllegalStateException().isThrownBy(() -> this.users.create("another-user", "Another User", this.audit))
					.withMessage("Audit event was not stored");
			assertThat(this.users.findByUsername("another-user")).isEmpty();
			assertThatIllegalStateException().isThrownBy(() -> this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit))
					.withMessage("Audit event was not stored");
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password").query(Long.class).single()).isZero();
			assertThat(this.users.findById(user.id())).contains(user);
			assertThat(auditCount()).isEqualTo(1);
		}
		finally {
			this.jdbc.sql("DROP TRIGGER IF EXISTS audit_test_suppress ON iam_security_audit").update();
			this.jdbc.sql("DROP FUNCTION audit_test_suppress_insert()").update();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "actor", "source", "correlation_id", "target_user_id", "action", "id", "after-altered", "after-deleted" })
	void changedOrRemovedAuditContentCannotCommitTheRelatedBusinessWrite(String changed) {
		String body = switch (changed) {
			case "actor" -> "NEW.actor='anonymous'; RETURN NEW;";
			case "source" -> "NEW.source='altered'; RETURN NEW;";
			case "action" -> "NEW.action='user_enabled'; RETURN NEW;";
			case "after-altered" -> "UPDATE iam_security_audit SET actor='anonymous' WHERE id=NEW.id; RETURN NEW;";
			case "after-deleted" -> "DELETE FROM iam_security_audit WHERE id=NEW.id; RETURN NEW;";
			default -> "NEW." + changed + "=gen_random_uuid(); RETURN NEW;";
		};
		auditFault(changed.startsWith("after-") ? "AFTER" : "BEFORE", body);
		try {
			assertThatIllegalStateException().isThrownBy(() -> this.users.create("alice", "Alice", this.audit)).withMessage("Audit event does not match stored state");
			assertThat(this.users.findByUsername("alice")).isEmpty(); assertThat(auditCount()).isZero();
		}
		finally { removeAuditFault(); }
		this.users.create("alice", "Alice", this.audit); assertThat(auditCount()).isEqualTo(1);
	}

	@Test
	void aChangedObjectTargetCannotBeAcceptedAsTheRequestedAudit() {
		auditFault("BEFORE", "NEW.target_id=gen_random_uuid(); RETURN NEW;");
		try {
			var target = new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, UUID.randomUUID());
			assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx ->
					this.audits.recordTargetSuccess(Action.RESOURCE_CREATED, target, this.audit))).withMessage("Audit event does not match stored state");
			assertThat(auditCount()).isZero();
		}
		finally { removeAuditFault(); }
	}

	@Test
	void aChangedFailureAuditCannotCommitTheRelatedDeniedDecision() {
		auditFault("BEFORE", "IF NEW.action='password_auth_failed' THEN NEW.actor='anonymous'; END IF; RETURN NEW;");
		try {
			assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.users.create("alice", "Alice", this.audit);
				this.audits.recordFailure(Action.PASSWORD_AUTH_FAILED, null, this.audit);
			})).withMessage("Audit event does not match stored state");
			assertThat(this.users.findByUsername("alice")).isEmpty(); assertThat(auditCount()).isZero();
		}
		finally { removeAuditFault(); }
	}

	private void auditFault(String timing, String body) {
		this.jdbc.sql("CREATE FUNCTION audit_test_change_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql("CREATE TRIGGER audit_test_change " + timing + " INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION audit_test_change_insert()").update();
	}

	private void removeAuditFault() {
		this.jdbc.sql("DROP TRIGGER IF EXISTS audit_test_change ON iam_security_audit").update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS audit_test_change_insert()").update();
	}

	@Test
	void refusesSuccessEventsOutsideTheBusinessTransaction() {
		assertThatThrownBy(() -> this.audits.recordSuccess(Action.USER_CREATED, UUID.randomUUID(), this.audit))
				.isInstanceOf(IllegalTransactionStateException.class);
		assertThat(auditCount()).isZero();
	}

	@Test
	void requiresExplicitAuditContextBeforeWritingBusinessData() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.create("alice", "Alice", null));
		assertThat(this.users.findByUsername("alice")).isEmpty();
		assertThat(auditCount()).isZero();
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", null));
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password").query(Long.class).single()).isZero();
		assertThat(auditCount()).isEqualTo(1);
	}

	@ParameterizedTest
	@MethodSource("invalidAuditFields")
	void databaseRejectsInvalidAuditFields(String column, Object value) {
		Map<String, Object> values = new HashMap<>(Map.of("id", UUID.randomUUID(), "actor", this.audit.actor(),
				"source", this.audit.source(), "correlationId", this.audit.correlationId(), "targetUserId", UUID.randomUUID(),
				"action", "user_created", "outcome", "success"));
		values.put(column, value);
		assertThatThrownBy(() -> this.jdbc.sql("""
				INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
				VALUES (:id, :actor, :source, :correlationId, :targetUserId, :action, :outcome)
				""").params(values).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(auditCount()).isZero();
	}

	static Stream<Arguments> invalidAuditFields() {
		return Stream.of(Arguments.of("actor", ""), Arguments.of("actor", "system:iam\n"),
				Arguments.of("actor", "a".repeat(129)), Arguments.of("source", ""), Arguments.of("source", "internal\n"),
				Arguments.of("source", "s".repeat(65)), Arguments.of("correlationId", null), Arguments.of("targetUserId", null),
				Arguments.of("action", "unknown"), Arguments.of("action", "user_info_rejected"), Arguments.of("outcome", "failure"));
	}

	@ParameterizedTest
	@CsvSource({ "31,user_info_rejected,protocol:userinfo", "34,introspection_rejected,protocol:introspection" })
	void protocolRejectionAuditUpgradePreservesExistingDecisionsAndOnlyAllowsTheNewFailureOutcome(String version, String action, String source) throws Exception {
		String schema = "protocol_audit_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
					.schemas(schema).defaultSchema(schema).target(version).load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema); var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				previous.sql("INSERT INTO iam_security_audit(id,actor,source,correlation_id,action,outcome) VALUES (:id,'anonymous','protocol:token',:correlation,'token_request_rejected','failure')")
						.param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).update();
				String legacy = previous.sql("SELECT row_to_json(r)::text FROM iam_security_audit r").query(String.class).single();
				assertThatThrownBy(() -> previous.sql("INSERT INTO iam_security_audit(id,actor,source,correlation_id,action,outcome) VALUES (:id,'anonymous',:source,:correlation,:action,'failure')")
						.param("id", UUID.randomUUID()).param("source", source).param("action", action).param("correlation", UUID.randomUUID()).update()).isInstanceOf(DataIntegrityViolationException.class);
				Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
						.schemas(schema).defaultSchema(schema).load().migrate();
				assertThat(previous.sql("SELECT row_to_json(r)::text FROM iam_security_audit r").query(String.class).single()).isEqualTo(legacy);
				for (boolean identified : new boolean[] { false, true }) {
					UUID subject = identified ? UUID.randomUUID() : null;
					previous.sql("INSERT INTO iam_security_audit(id,actor,source,correlation_id,target_user_id,action,outcome) VALUES (:id,:actor,:source,:correlation,:subject,:action,'failure')")
							.param("id", UUID.randomUUID()).param("actor", identified ? "user:" + subject : "anonymous").param("source", source).param("action", action).param("correlation", UUID.randomUUID()).param("subject", subject).update();
				}
				assertThat(previous.sql("SELECT count(*) FROM iam_security_audit").query(Long.class).single()).isEqualTo(3);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET outcome='success' WHERE action=:action").param("action", action).update()).isInstanceOf(DataIntegrityViolationException.class);
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	@Test
	void upgradesExistingV1DataWithoutInventingHistoricalAuditEvents() throws Exception {
		String schema = "audit_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
					.schemas(schema).defaultSchema(schema).target("1").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				JdbcClient previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID id = UUID.randomUUID();
				String hash = this.passwords.hash("seven amber lanterns by the river", "alice");
				previous.sql("INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'alice', 'Alice')").param("id", id).update();
				previous.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)").param("id", id).param("hash", hash).update();
				Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
						.schemas(schema).defaultSchema(schema).load().migrate();
				assertThat(previous.sql("SELECT username FROM iam_user WHERE id = :id").param("id", id).query(String.class).single()).isEqualTo("alice");
				assertThat(previous.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", id).query(String.class).single()).isEqualTo(hash);
				assertThat(previous.sql("SELECT count(*) FROM iam_security_audit").query(Long.class).single()).isZero();
				assertThat(previous.sql("SELECT count(*) FROM flyway_schema_history WHERE success AND version IN ('1', '2')")
						.query(Long.class).single()).isEqualTo(2);
			}
		}
		finally {
			this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update();
		}
	}

	private long auditCount() {
		return this.jdbc.sql("SELECT count(*) FROM iam_security_audit").query(Long.class).single();
	}

}
