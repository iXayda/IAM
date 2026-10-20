package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityUserRolePage;
import com.ixayda.iam.model.SecurityAuditContext;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserRolesIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:binding-test", "internal:bindings", UUID.randomUUID());
	@Autowired private IdentityUserRoles bindings;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private UUID userId;
	private UUID resourceId;
	private UUID roleId;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user,iam_resource,iam_security_audit CASCADE").update();
		// The user cascade also clears the administrator lifecycle's user references.
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap (singleton) VALUES (1)").update();
		this.userId = this.users.create("alice", "Alice", AUDIT).id();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_user_role", "iam_user_resource_role_revision", "iam_security_audit")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS binding_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS binding_test_fault()").update();
		this.jdbc.sql("TRUNCATE iam_user_role,iam_user_resource_role_revision").update();
	}

	@Test
	void directAssignmentsHaveIndependentRevisionsAndCannotGrantIamAdministratorMembership() {
		var user = this.users.findById(this.userId).orElseThrow();
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).version()).isZero();
		var created = this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		assertThat(created.changed()).isTrue();
		assertThat(created.version()).isEqualTo(1);
		assertThat(created.resourceId()).isEqualTo(this.resourceId);
		var page = this.bindings.search(this.userId, this.resourceId, 20, null);
		assertThat(page.version()).isEqualTo(1);
		assertThat(page.items()).singleElement().satisfies(binding -> {
			assertThat(binding.userId()).isEqualTo(this.userId);
			assertThat(binding.roleId()).isEqualTo(this.roleId);
			assertThat(binding.resourceId()).isEqualTo(this.resourceId);
		});
		assertThat(this.users.findById(this.userId)).contains(user);
		assertThat(this.resources.findById(this.resourceId).orElseThrow().version()).isEqualTo(1);
		assertThat(this.roles.findById(this.roleId).orElseThrow().version()).isEqualTo(1);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_administrator WHERE user_id=:id").param("id", this.userId).query(Long.class).single()).isZero();
		var event = this.jdbc.sql("SELECT action,actor,source,target_user_id,target_type,target_id,correlation_id FROM iam_security_audit WHERE action='user_role_granted'").query().singleRow();
		assertThat(event).containsEntry("target_user_id", this.userId).containsEntry("target_type", "role").containsEntry("target_id", this.roleId)
				.containsEntry("actor", AUDIT.actor()).containsEntry("source", AUDIT.source()).containsEntry("correlation_id", AUDIT.correlationId());
	}

	@Test
	void noOpsAndStaleRevisionsDoNotWriteAndRevocationNeverResetsTheRevision() {
		assertThat(this.bindings.change(this.userId, this.roleId, 0, false, AUDIT).changed()).isFalse();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user_resource_role_revision").query(Long.class).single()).isZero();
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var before = snapshot();
		assertThat(this.bindings.change(this.userId, this.roleId, 1, true, AUDIT).changed()).isFalse();
		assertThatThrownBy(() -> this.bindings.change(this.userId, this.roleId, 0, true, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(before);
		var removed = this.bindings.change(this.userId, this.roleId, 1, false, AUDIT);
		assertThat(removed.version()).isEqualTo(2);
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).items()).isEmpty();
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).version()).isEqualTo(2);
		assertThatThrownBy(() -> this.bindings.change(this.userId, this.roleId, 0, true, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(this.bindings.change(this.userId, this.roleId, 2, true, AUDIT).version()).isEqualTo(3);
	}

	@Test
	void assignmentsAreScopedToTheirUserAndResourceAndCanBeInspectedOrRevokedWhenDisabled() {
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		UUID otherUser = this.users.create("bobby", "Bob", AUDIT).id();
		assertThat(this.bindings.search(otherUser, this.resourceId, 20, null).items()).isEmpty();
		assertThat(this.bindings.search(otherUser, this.resourceId, 20, null).version()).isZero();
		UUID otherResource = this.resources.create("urn:example:billing", "Billing", AUDIT).id();
		UUID otherRole = this.roles.create(otherResource, "reader", "Reader", AUDIT).id();
		assertThat(this.bindings.change(this.userId, otherRole, 0, true, AUDIT).version()).isEqualTo(1);
		this.roles.setEnabled(this.roleId, 1, false, AUDIT);
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		this.states.disable(this.userId, AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.bindings.change(this.userId, this.roleId, 1, true, AUDIT)).isInstanceOf(IdentityUserRoles.BindingNotAllowedException.class);
		assertThat(snapshot()).isEqualTo(before);
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).items()).hasSize(1);
		assertThat(this.bindings.change(this.userId, this.roleId, 1, false, AUDIT).changed()).isTrue();
		assertThat(this.bindings.search(this.userId, otherResource, 20, null).items()).hasSize(1);
	}

	@Test
	void concurrentEditsWithTheSameRevisionHaveExactlyOneWinner() throws Exception {
		UUID writer = this.roles.create(this.resourceId, "writer", "Writer", AUDIT).id();
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var futures = List.of(this.roleId, writer).stream().map(role -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.bindings.change(this.userId, role, 0, true, AUDIT); return true; }
				catch (OptimisticLockingFailureException ex) { return false; }
			})).toList();
			start.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var future : futures) { outcomes.add(future.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).items()).hasSize(1);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='user_role_granted'").query(Long.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "grant-audit", "revoke-audit", "grant-deferred", "revoke-deferred", "grant-header", "revoke-header", "grant-binding", "revoke-binding" })
	void storageAuditSuppressionAndDeferredCommitFailuresRollBackTheEntireChange(String operation) {
		boolean grant = operation.startsWith("grant");
		if (!grant) { this.bindings.change(this.userId, this.roleId, 0, true, AUDIT); }
		var before = snapshot();
		String table = operation.endsWith("header") ? "iam_user_resource_role_revision" : operation.endsWith("binding") ? "iam_user_role" : "iam_security_audit";
		boolean deferred = operation.endsWith("deferred");
		String change = table.equals("iam_security_audit") ? "INSERT" : table.equals("iam_user_role") && !grant ? "DELETE" : grant ? "INSERT" : "UPDATE";
		String body = operation.endsWith("header") || operation.endsWith("binding") ? "RETURN NULL;" : "RAISE EXCEPTION 'test assignment failure';";
		this.jdbc.sql("CREATE FUNCTION binding_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER binding_test_fault AFTER " : "CREATE TRIGGER binding_test_fault BEFORE ")
				+ change + " ON " + table + (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION binding_test_fault()").update();
		assertThatThrownBy(() -> this.bindings.change(this.userId, this.roleId, grant ? 0 : 1, grant, AUDIT)).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void anOuterRollbackAlsoRemovesTheRevisionAssignmentAndAudit() {
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
			tx.setRollbackOnly();
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void anAlteredGrantCannotPublishSuccessOrAdvanceTheAssignmentRevision() {
		UUID otherRole = this.roles.create(this.resourceId, "writer", "Writer", AUDIT).id();
		var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION binding_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.role_id='"
				+ otherRole + "'::uuid; RETURN NEW; END $$").update();
		this.jdbc.sql("CREATE TRIGGER binding_test_fault BEFORE INSERT ON iam_user_role FOR EACH ROW EXECUTE FUNCTION binding_test_fault()").update();
		assertThatIllegalStateException().isThrownBy(() -> this.bindings.change(this.userId, this.roleId, 0, true, AUDIT));
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "user", "resource", "role" })
	void eachInactiveSubjectIndependentlyPreventsANewAssignment(String subject) {
		switch (subject) {
			case "user" -> this.states.disable(this.userId, AUDIT);
			case "resource" -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
			default -> this.roles.setEnabled(this.roleId, 1, false, AUDIT);
		}
		var before = snapshot();
		assertThatThrownBy(() -> this.bindings.change(this.userId, this.roleId, 0, true, AUDIT)).isInstanceOf(IdentityUserRoles.BindingNotAllowedException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "user", "resource", "role" })
	void aGrantWaitingForALockRechecksTheCommittedSubjectState(String subject) throws Exception {
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var holder = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				switch (subject) {
					case "user" -> this.states.disable(this.userId, AUDIT);
					case "resource" -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
					default -> this.roles.setEnabled(this.roleId, 1, false, AUDIT);
				}
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var grant = executor.submit(() -> {
				try { this.bindings.change(this.userId, this.roleId, 0, true, AUDIT); return false; }
				catch (IdentityUserRoles.BindingNotAllowedException ex) { return true; }
			});
			try {
				await().atMost(java.time.Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FOR UPDATE%'")
						.query(Long.class).single() > 0);
			}
			finally { release.countDown(); }
			holder.get(10, TimeUnit.SECONDS);
			assertThat(grant.get(10, TimeUnit.SECONDS)).isTrue();
		}
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).items()).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='user_role_granted'").query(Long.class).single()).isZero();
	}

	@Test
	void paginationIsBoundToTheUserResourceAndExactAssignmentRevision() {
		for (int i = 0; i < 3; i++) {
			UUID role = this.roles.create(this.resourceId, "reader_" + i, "Reader " + i, AUDIT).id();
			this.bindings.change(this.userId, role, i, true, AUDIT);
		}
		var first = this.bindings.search(this.userId, this.resourceId, 2, null);
		assertThat(first.version()).isEqualTo(3);
		assertThat(first.items()).hasSize(2);
		var last = this.bindings.search(this.userId, this.resourceId, 100, first.nextCursor());
		assertThat(last.items()).hasSize(1).doesNotContainAnyElementsOf(first.items());
		assertThat(last.nextCursor()).isNull();
		assertThatIllegalArgumentException().isThrownBy(() -> this.bindings.search(UUID.randomUUID(), this.resourceId, 2, first.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.bindings.search(this.userId, UUID.randomUUID(), 2, first.nextCursor()));
		this.bindings.change(this.userId, this.roleId, 3, true, AUDIT);
		assertThatThrownBy(() -> this.bindings.search(this.userId, this.resourceId, 2, first.nextCursor())).isInstanceOf(OptimisticLockingFailureException.class);
		assertThatIllegalArgumentException().isThrownBy(() -> new IdentityUserRolePage.Cursor(this.userId, this.resourceId, 1,
				Instant.parse("2026-10-01T00:00:00.000000001Z"), this.roleId));
		assertThatIllegalArgumentException().isThrownBy(() -> this.bindings.search(this.userId, this.resourceId, 101, null));
	}

	@Test
	void databaseRelationsPreventCrossResourceAssignmentsAndRevisionDeletionOrRewriting() {
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_user_resource_role_revision").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user_resource_role_revision SET version=1").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user_role SET created_at=clock_timestamp()").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
		UUID other = this.resources.create("urn:other", "Other", AUDIT).id();
		UUID otherUser = this.users.create("bobby", "Bob", AUDIT).id();
		this.jdbc.sql("INSERT INTO iam_user_resource_role_revision(user_id,resource_id) VALUES (:user,:resource)").param("user", otherUser).param("resource", other).update();
		assertThatThrownBy(() -> this.jdbc.sql("INSERT INTO iam_user_role(user_id,resource_id,role_id) VALUES (:user,:resource,:role)")
				.param("user", otherUser).param("resource", other).param("role", this.roleId).update())
				.isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("foreign key constraint");
	}

	@ParameterizedTest
	@ValueSource(strings = { "target_user_id=NULL", "target_id=NULL", "target_type=NULL", "target_type='resource'", "outcome='failure'" })
	void bindingAuditConstraintsRequireBothTheUserAndTheTypedRole(String assignment) {
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET " + assignment + " WHERE action='user_role_granted'").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void missingTargetsAndInvalidVersionsAreRejectedWithoutWriting() {
		var before = snapshot();
		assertThatThrownBy(() -> this.bindings.change(UUID.randomUUID(), this.roleId, 0, true, AUDIT)).isInstanceOf(java.util.NoSuchElementException.class);
		assertThatThrownBy(() -> this.bindings.change(this.userId, UUID.randomUUID(), 0, true, AUDIT)).isInstanceOf(java.util.NoSuchElementException.class);
		assertThatIllegalArgumentException().isThrownBy(() -> this.bindings.change(this.userId, this.roleId, -1, true, AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.bindings.change(this.userId, this.roleId, 0, true, null));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradingV23RetainsUsersResourcesRolesAndAuditWithoutInventingAssignments() throws Exception {
		String schema = "binding_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("23").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				var tables = List.of("iam_user", "iam_resource", "iam_resource_role", "iam_security_audit");
				for (String table : tables) { copyRows(old, table); }
				var before = tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				var flyway = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("24").load();
				assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
				var after = tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				assertThat(after).isEqualTo(before);
				assertThat(old.sql("SELECT count(*) FROM iam_user_role").query(Long.class).single()).isZero();
				assertThat(old.sql("SELECT count(*) FROM iam_user_resource_role_revision").query(Long.class).single()).isZero();
				assertThat(flyway.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private List<List<String>> snapshot() {
		return List.of("iam_user", "iam_resource", "iam_resource_role", "iam_user_resource_role_revision", "iam_user_role", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

}
