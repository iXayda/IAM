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
import com.ixayda.iam.model.IdentityResourceRole;
import com.ixayda.iam.model.IdentityResourceRolePage;
import com.ixayda.iam.model.SecurityAuditContext;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
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
class IdentityResourceRolesIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:role-test", "internal:roles", UUID.randomUUID());
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityResources resources;
	@Autowired private JdbcClient jdbc;
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private PlatformTransactionManager transactions;
	private UUID resourceId;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_resource, iam_resource_role, iam_security_audit CASCADE").update();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
	}

	@AfterEach
	void removeFaults() {
		this.jdbc.sql("DROP TRIGGER IF EXISTS role_test_fault ON iam_resource_role").update();
		this.jdbc.sql("DROP TRIGGER IF EXISTS role_test_fault ON iam_security_audit").update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS role_test_fault()").update();
	}

	@Test
	void rolesHaveStableResourceScopedCodesAndTypedSecretFreeAudits() {
		var role = this.roles.create(this.resourceId, "reader", "Cafe\u0301 阅读 😀", AUDIT);
		assertThat(role.displayName()).isEqualTo("Café 阅读 😀");
		assertThat(role.version()).isEqualTo(1);
		assertThat(role.status()).isEqualTo(IdentityResourceRole.Status.ACTIVE);
		assertThat(role.resourceId()).isEqualTo(this.resourceId);
		assertThat(this.roles.findById(role.id())).contains(role);
		assertThat(this.roles.findByCode(this.resourceId, "reader")).contains(role);
		assertThatThrownBy(() -> this.roles.create(this.resourceId, "reader", "Duplicate", AUDIT)).isInstanceOf(DuplicateKeyException.class);
		var other = this.resources.create("urn:example:billing", "Billing", AUDIT);
		assertThat(this.roles.create(other.id(), "reader", "Reader", AUDIT).id()).isNotEqualTo(role.id());
		assertThat(this.resources.findById(this.resourceId).orElseThrow().version()).isEqualTo(1);
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE target_id = :id").param("id", role.id()).query().singleRow();
		assertThat(event).containsEntry("action", "resource_role_created").containsEntry("target_type", "role")
				.containsEntry("target_user_id", null).containsEntry("actor", AUDIT.actor()).containsEntry("source", AUDIT.source())
				.containsEntry("correlation_id", AUDIT.correlationId());
		assertThat(event.toString()).doesNotContain(role.code(), role.displayName());
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "Reader", "1reader", "_reader", "reader-role", "reader.role", "reader role", " reader", "reader ", "reader\n", "用户" })
	void roleCodesAreExactAndNeverSilentlyRewritten(String code) {
		var before = snapshot();
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.create(this.resourceId, code, "Reader", AUDIT));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void lengthUnicodeAndMissingInputBoundariesDoNotProducePartialRoles() {
		var role = this.roles.create(this.resourceId, "a".repeat(64), "😀".repeat(128), AUDIT);
		assertThat(role.code()).hasSize(64);
		for (String name : List.of("", " ", "\u00a0", "x\n", "\ud800", "😀".repeat(129), "x".repeat(65_537))) {
			assertThatIllegalArgumentException().isThrownBy(() -> this.roles.create(this.resourceId, "writer", name, AUDIT));
		}
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.create(this.resourceId, "a".repeat(65), "Name", AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.create(null, "writer", "Name", AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.create(this.resourceId, "writer", "Name", null));
		assertThatThrownBy(() -> this.roles.create(UUID.randomUUID(), "writer", "Name", AUDIT)).isInstanceOf(java.util.NoSuchElementException.class);
		assertThat(this.roles.search(this.resourceId, null, 100, null).items()).containsExactly(role);
	}

	@Test
	void versionedChangesDoNotChangeRoleIdentityAndNoOpsDoNotGenerateChangeEvents() {
		var original = this.roles.create(this.resourceId, "reader", "Reader", AUDIT);
		var changed = this.roles.updateDisplayName(original.id(), 1, "Read orders", AUDIT);
		assertThat(changed.id()).isEqualTo(original.id());
		assertThat(changed.code()).isEqualTo(original.code());
		assertThat(changed.createdAt()).isEqualTo(original.createdAt());
		assertThat(changed.version()).isEqualTo(2);
		var before = snapshot();
		assertThat(this.roles.updateDisplayName(original.id(), 2, "Read orders", AUDIT)).isEqualTo(changed);
		assertThat(this.roles.setEnabled(original.id(), 2, true, AUDIT)).isEqualTo(changed);
		assertThatThrownBy(() -> this.roles.setEnabled(original.id(), 1, false, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(before);
		var disabled = this.roles.setEnabled(original.id(), 2, false, AUDIT);
		assertThat(disabled.status()).isEqualTo(IdentityResourceRole.Status.DISABLED);
		assertThat(this.roles.setEnabled(original.id(), 3, true, AUDIT).version()).isEqualTo(4);
		assertThat(this.jdbc.sql("SELECT action FROM iam_security_audit WHERE target_type = 'role' ORDER BY recorded_at, id").query(String.class).list())
				.containsExactly("resource_role_created", "resource_role_updated", "resource_role_disabled", "resource_role_enabled");
	}

	@Test
	void anInactiveParentPreventsCreatingOrEnablingRolesButAllowsInspectionAndRestriction() {
		var role = this.roles.create(this.resourceId, "reader", "Reader", AUDIT);
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.roles.create(this.resourceId, "writer", "Writer", AUDIT)).isInstanceOf(IdentityResourceRoles.ResourceInactiveException.class);
		assertThatThrownBy(() -> this.roles.setEnabled(role.id(), 1, true, AUDIT)).isInstanceOf(IdentityResourceRoles.ResourceInactiveException.class);
		assertThat(snapshot()).isEqualTo(before);
		assertThat(this.roles.search(this.resourceId, null, 100, null).items()).containsExactly(role);
		assertThat(this.roles.updateDisplayName(role.id(), 1, "Read", AUDIT).version()).isEqualTo(2);
		assertThat(this.roles.setEnabled(role.id(), 2, false, AUDIT).version()).isEqualTo(3);
	}

	@Test
	void theDatabasePreventsIdentityChangesDeletionAndCodeReuse() {
		var role = this.roles.create(this.resourceId, "reader", "Reader", AUDIT);
		UUID other = this.resources.create("urn:other", "Other", AUDIT).id();
		var before = snapshot();
		for (String field : List.of("id = gen_random_uuid()", "resource_id = '" + other + "'", "code = 'writer'", "created_at = clock_timestamp()")) {
			assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_resource_role SET " + field + ", version = version + 1, updated_at = clock_timestamp()").update())
					.isInstanceOf(DataIntegrityViolationException.class);
		}
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_resource_role").update()).isInstanceOf(DataIntegrityViolationException.class);
		this.roles.setEnabled(role.id(), 1, false, AUDIT);
		assertThatThrownBy(() -> this.roles.create(this.resourceId, "reader", "Reused", AUDIT)).isInstanceOf(DuplicateKeyException.class);
		assertThat(snapshot().getFirst()).isEqualTo(before.getFirst());
	}

	@Test
	void concurrentWritersRespectUniqueCodesAndExpectedVersions() throws Exception {
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(3)) {
			var results = java.util.stream.IntStream.range(0, 3).mapToObj(i -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.roles.create(this.resourceId, "reader", "Reader", AUDIT); return true; }
				catch (DuplicateKeyException ex) { return false; }
			})).toList();
			start.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var result : results) { outcomes.add(result.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false, false);
		}
		var role = this.roles.findByCode(this.resourceId, "reader").orElseThrow();
		var next = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var results = java.util.stream.IntStream.range(0, 2).mapToObj(i -> executor.submit(() -> {
				assertThat(next.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.roles.updateDisplayName(role.id(), 1, "Reader " + i, AUDIT); return true; }
				catch (OptimisticLockingFailureException ex) { return false; }
			})).toList();
			next.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var result : results) { outcomes.add(result.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.roles.findById(role.id()).orElseThrow().version()).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE target_type = 'role'").query(Long.class).single()).isEqualTo(2);
	}

	@Test
	void aCreatorWaitingForTheParentLockRechecksItsCommittedStatus() throws Exception {
		var locked = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var holder = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
				locked.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var creator = executor.submit(() -> {
				try { this.roles.create(this.resourceId, "reader", "Reader", AUDIT); return false; }
				catch (IdentityResourceRoles.ResourceInactiveException ex) { return true; }
			});
			try {
				await().atMost(java.time.Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%FROM iam_resource WHERE id%'").query(Long.class).single() > 0);
			}
			finally { release.countDown(); }
			holder.get(10, TimeUnit.SECONDS);
			assertThat(creator.get(10, TimeUnit.SECONDS)).isTrue();
		}
		assertThat(this.roles.search(this.resourceId, null, 100, null).items()).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE target_type = 'role'").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "create", "rename", "disable", "enable", "deferred" })
	void auditAndCommitFailuresRollBackEveryKindOfRoleChange(String operation) {
		var role = this.roles.create(this.resourceId, "reader", "Reader", AUDIT);
		if (operation.equals("enable")) { role = this.roles.setEnabled(role.id(), 1, false, AUDIT); }
		var current = role;
		var before = snapshot();
		fault("iam_security_audit", "INSERT", "RAISE EXCEPTION 'test role audit failure';", operation.equals("deferred"));
		assertThatThrownBy(() -> {
			switch (operation) {
				case "create" -> this.roles.create(this.resourceId, "writer", "Writer", AUDIT);
				case "rename" -> this.roles.updateDisplayName(current.id(), current.version(), "Changed", AUDIT);
				case "enable" -> this.roles.setEnabled(current.id(), current.version(), true, AUDIT);
				default -> this.roles.setEnabled(current.id(), current.version(), false, AUDIT);
			}
		}).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "create-suppressed", "create-altered", "update-suppressed", "update-altered" })
	void suppressedOrAlteredPersistenceNeverCreatesASuccessfulRoleOrAudit(String operation) {
		var role = this.roles.create(this.resourceId, "reader", "Reader", AUDIT);
		var before = snapshot();
		fault("iam_resource_role", operation.startsWith("create") ? "INSERT" : "UPDATE",
				operation.endsWith("suppressed") ? "RETURN NULL;" : "NEW.display_name := 'Altered'; RETURN NEW;", false);
		assertThatIllegalStateException().isThrownBy(() -> {
			if (operation.startsWith("create")) { this.roles.create(this.resourceId, "writer", "Writer", AUDIT); }
			else { this.roles.updateDisplayName(role.id(), 1, "Changed", AUDIT); }
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void rolePagingUsesStableUuidOrderAndCannotSwitchParentOrStateFilters() {
		for (int i = 1; i <= 5; i++) {
			this.jdbc.sql("INSERT INTO iam_resource_role(id,resource_id,code,display_name,status,created_at,updated_at) VALUES (:id,:parent,:code,'Fixture',:status,'2026-10-01T00:00:00Z','2026-10-01T00:00:00Z')")
					.param("id", new UUID(0, i)).param("parent", this.resourceId).param("code", "role_" + i)
					.param("status", i % 2 == 0 ? "disabled" : "active").update();
		}
		var first = this.roles.search(this.resourceId, null, 2, null);
		assertThat(first.items()).extracting(IdentityResourceRole::id).containsExactly(new UUID(0, 1), new UUID(0, 2));
		var last = this.roles.search(this.resourceId, null, 100, first.nextCursor());
		assertThat(last.items()).extracting(IdentityResourceRole::id).containsExactly(new UUID(0, 3), new UUID(0, 4), new UUID(0, 5));
		assertThat(last.nextCursor()).isNull();
		assertThat(this.roles.search(this.resourceId, IdentityResourceRole.Status.DISABLED, 100, null).items()).hasSize(2);
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.search(UUID.randomUUID(), null, 2, first.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.search(this.resourceId, IdentityResourceRole.Status.ACTIVE, 2, first.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.roles.search(this.resourceId, null, 101, null));
		assertThatIllegalArgumentException().isThrownBy(() -> new IdentityResourceRolePage.Cursor(Instant.parse("2026-10-01T00:00:00.000000001Z"), UUID.randomUUID(), this.resourceId, null));
	}

	@ParameterizedTest
	@ValueSource(strings = { "target_type = NULL", "target_type = 'resource'", "target_id = NULL", "target_user_id = gen_random_uuid()", "outcome = 'failure'" })
	void theDatabaseRequiresTypedRoleAuditTargets(String assignment) {
		this.roles.create(this.resourceId, "reader", "Reader", AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET " + assignment + " WHERE target_type = 'role'").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradingV22PreservesResourcesAndAuditsAndDoesNotInventRoles() throws Exception {
		String schema = "role_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
					.schemas(schema).defaultSchema(schema).target("22").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				copyRows(old, "iam_resource");
				copyRows(old, "iam_security_audit");
				var before = List.of("iam_resource", "iam_security_audit").stream()
						.map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				var flyway = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
						.schemas(schema).defaultSchema(schema).target("23").load();
				assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
				var after = List.of("iam_resource", "iam_security_audit").stream()
						.map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				assertThat(after).isEqualTo(before);
				assertThat(old.sql("SELECT count(*) FROM iam_resource_role").query(Long.class).single()).isZero();
				assertThat(flyway.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private List<List<String>> snapshot() {
		return List.of("iam_resource", "iam_resource_role", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

	private void fault(String table, String operation, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION role_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER role_test_fault AFTER " : "CREATE TRIGGER role_test_fault BEFORE ")
				+ operation + " ON " + table + (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION role_test_fault()").update();
	}

}
