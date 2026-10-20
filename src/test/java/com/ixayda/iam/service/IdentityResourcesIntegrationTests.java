package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourcePage;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.model.SecurityAuditTarget;

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
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityResourcesIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:resource-test", "internal:resources", UUID.randomUUID());
	@Autowired private IdentityResources resources;
	@Autowired private SecurityAudits audits;
	@Autowired private JdbcClient jdbc;
	@Autowired private PostgreSQLContainer postgres;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_resource, iam_security_audit").update();
	}

	@AfterEach
	void removeFaults() {
		this.jdbc.sql("DROP TRIGGER IF EXISTS resource_test_fault ON iam_resource").update();
		this.jdbc.sql("DROP TRIGGER IF EXISTS resource_test_fault ON iam_security_audit").update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS resource_test_fault()").update();
	}

	@Test
	void createsStableCaseSensitiveAudiencesAndRecordsTheResourceAsTheAuditTarget() {
		var first = this.resources.create("urn:example:orders", "Cafe\u0301 订单 😀", AUDIT);
		var second = this.resources.create("urn:example:Orders", "Orders", AUDIT);
		assertThat(first.id()).isNotEqualTo(second.id());
		assertThat(first.displayName()).isEqualTo("Café 订单 😀");
		assertThat(first.status()).isEqualTo(IdentityResource.Status.ACTIVE);
		assertThat(first.version()).isEqualTo(1);
		assertThat(first.createdAt()).isBetween(Instant.now().minusSeconds(10), Instant.now());
		assertThat(first.updatedAt()).isAfterOrEqualTo(first.createdAt());
		assertThat(this.resources.findById(first.id())).contains(first);
		assertThat(this.resources.findByAudience("urn:example:orders")).contains(first);
		assertThat(this.resources.findByAudience("URN:EXAMPLE:ORDERS")).isEmpty();
		var events = this.audits.search(new SecurityAuditFilter(null, null, null, null, null, AUDIT.source(), null, null), 10, null).items();
		assertThat(events).hasSize(2).allSatisfy(event -> {
			assertThat(event.targetUserId()).isNull();
			assertThat(event.target().type()).isEqualTo(SecurityAuditTarget.Type.RESOURCE);
			assertThat(event.context()).isEqualTo(AUDIT);
		});
		assertThat(events).extracting(event -> event.target().id()).containsExactlyInAnyOrder(first.id(), second.id());
		assertThat(snapshot().getLast()).allSatisfy(event -> assertThat(event).doesNotContain(first.audience(), first.displayName()));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", " urn:orders", "urn:orders ", "urn:orders\n", "urn:order\tservice", "中文", "a\u007f", "a\u0085" })
	void rejectsInvalidAudiencesBeforeWriting(String audience) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.create(audience, "Orders", AUDIT));
		assertThat(snapshot()).allSatisfy(rows -> assertThat(rows).isEmpty());
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", "\u00a0", "name\n", "name\u0085", "\ud800", "\udc00", "x\ud800y" })
	void rejectsInvalidDisplayNamesBeforeWriting(String display) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.create("urn:orders", display, AUDIT));
		assertThat(snapshot()).allSatisfy(rows -> assertThat(rows).isEmpty());
	}

	@Test
	void enforcesInputLengthBoundariesWithoutTrimmingOrLowercasing() {
		var resource = this.resources.create("a".repeat(256), "😀".repeat(128), AUDIT);
		assertThat(resource.audience()).hasSize(256);
		assertThat(resource.displayName()).isEqualTo("😀".repeat(128));
		assertThat(this.resources.create("urn:spaces", " Orders ", AUDIT).displayName()).isEqualTo(" Orders ");
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.create("a".repeat(257), "Orders", AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.create("urn:oversized", "😀".repeat(129), AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.create("urn:huge", "x".repeat(65_537), AUDIT));
	}

	@Test
	void updatesOnlyMutableFieldsAndLeavesNoOpOperationsAndStaleVersionsUnchanged() {
		var created = this.resources.create("urn:orders", "Orders", AUDIT);
		var renamed = this.resources.updateDisplayName(created.id(), 1, "New orders", AUDIT);
		assertThat(renamed.version()).isEqualTo(2);
		assertThat(renamed.id()).isEqualTo(created.id());
		assertThat(renamed.audience()).isEqualTo(created.audience());
		assertThat(renamed.createdAt()).isEqualTo(created.createdAt());
		assertThat(renamed.updatedAt()).isAfterOrEqualTo(created.updatedAt());
		var unchanged = snapshot();
		assertThat(this.resources.updateDisplayName(created.id(), 2, "New orders", AUDIT)).isEqualTo(renamed);
		assertThat(this.resources.setEnabled(created.id(), 2, true, AUDIT)).isEqualTo(renamed);
		assertThatThrownBy(() -> this.resources.setEnabled(created.id(), 1, true, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(unchanged);
		var disabled = this.resources.setEnabled(created.id(), 2, false, AUDIT);
		assertThat(disabled.status()).isEqualTo(IdentityResource.Status.DISABLED);
		assertThat(disabled.version()).isEqualTo(3);
		assertThat(this.resources.setEnabled(created.id(), 3, false, AUDIT)).isEqualTo(disabled);
		assertThat(this.resources.setEnabled(created.id(), 3, true, AUDIT).version()).isEqualTo(4);
		assertThat(this.jdbc.sql("SELECT action FROM iam_security_audit ORDER BY recorded_at, id").query(String.class).list())
				.containsExactly("resource_created", "resource_updated", "resource_disabled", "resource_enabled");
	}

	@Test
	void serializesConcurrentChangesAndDuplicateAudienceCreation() throws Exception {
		var created = this.resources.create("urn:orders", "Orders", AUDIT);
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var futures = java.util.stream.IntStream.range(0, 2).mapToObj(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.resources.updateDisplayName(created.id(), 1, "Name " + index, AUDIT); return true; }
				catch (OptimisticLockingFailureException expected) { return false; }
			})).toList();
			start.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var future : futures) { outcomes.add(future.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.resources.findById(created.id()).orElseThrow().version()).isEqualTo(2);
		var duplicateStart = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(4)) {
			var futures = java.util.stream.IntStream.range(0, 4).mapToObj(index -> executor.submit(() -> {
				assertThat(duplicateStart.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.resources.create("urn:duplicate", "Duplicate", AUDIT); return true; }
				catch (DuplicateKeyException expected) { return false; }
			})).toList();
			duplicateStart.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var future : futures) { outcomes.add(future.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false, false, false);
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'resource_created'").query(Long.class).single()).isEqualTo(2);
	}

	@ParameterizedTest
	@ValueSource(strings = { "create", "rename", "disable", "enable", "commit" })
	void mandatoryAuditAndCommitFailuresRollBackTheWholeResourceChange(String operation) {
		var resource = this.resources.create("urn:orders", "Orders", AUDIT);
		if (operation.equals("enable")) { resource = this.resources.setEnabled(resource.id(), 1, false, AUDIT); }
		var current = resource;
		var before = snapshot();
		installFault("iam_security_audit", "RAISE EXCEPTION 'test audit failure';", operation.equals("commit"), "INSERT");
		assertThatThrownBy(() -> {
			switch (operation) {
				case "create" -> this.resources.create("urn:new", "New", AUDIT);
				case "rename" -> this.resources.updateDisplayName(current.id(), current.version(), "Changed", AUDIT);
				case "enable" -> this.resources.setEnabled(current.id(), current.version(), true, AUDIT);
				default -> this.resources.setEnabled(current.id(), current.version(), false, AUDIT);
			}
		}).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "create-suppressed", "create-altered", "update-suppressed", "update-altered" })
	void detectsSuppressedOrAlteredPersistenceAndRollsBackItsAudit(String operation) {
		var resource = this.resources.create("urn:orders", "Orders", AUDIT);
		var before = snapshot();
		installFault("iam_resource", operation.endsWith("suppressed") ? "RETURN NULL;" : "NEW.display_name := 'Altered'; RETURN NEW;", false,
				operation.startsWith("create") ? "INSERT" : "UPDATE");
		assertThatIllegalStateException().isThrownBy(() -> {
			if (operation.startsWith("create")) { this.resources.create("urn:new", "New", AUDIT); }
			else { this.resources.updateDisplayName(resource.id(), 1, "New", AUDIT); }
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void resourceIdentityAndAudienceCannotBeChangedDeletedOrReused() {
		var resource = this.resources.create("urn:orders", "Orders", AUDIT);
		var before = snapshot();
		for (String assignment : List.of("id = gen_random_uuid()", "audience = 'urn:new'", "created_at = created_at + interval '1 second'", "version = 1", "status = 'invalid'")) {
			String version = assignment.startsWith("version") ? "" : ", version = version + 1";
			assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_resource SET " + assignment + version + ", updated_at = clock_timestamp()").update())
					.isInstanceOf(DataIntegrityViolationException.class);
		}
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_resource").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.resources.create(resource.audience(), "Duplicate", AUDIT)).isInstanceOf(DuplicateKeyException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void pagingUsesTheFullDatabaseOrderingAndBindsTheStatusFilter() {
		for (int i = 1; i <= 7; i++) {
			this.jdbc.sql("INSERT INTO iam_resource (id, audience, display_name, status, created_at, updated_at) VALUES (:id, :audience, 'Fixture', :status, '2026-10-01T01:02:03Z', '2026-10-01T01:02:03Z')")
					.param("id", new UUID(0, i)).param("audience", "urn:fixture:" + i).param("status", i % 2 == 0 ? "disabled" : "active").update();
		}
		var first = this.resources.search(null, 2, null);
		assertThat(first.items()).extracting(IdentityResource::id).containsExactly(new UUID(0, 1), new UUID(0, 2));
		var second = this.resources.search(null, 3, first.nextCursor());
		assertThat(second.items()).extracting(IdentityResource::id).containsExactly(new UUID(0, 3), new UUID(0, 4), new UUID(0, 5));
		var last = this.resources.search(null, 100, second.nextCursor());
		assertThat(last.items()).extracting(IdentityResource::id).containsExactly(new UUID(0, 6), new UUID(0, 7));
		assertThat(last.nextCursor()).isNull();
		assertThat(this.resources.search(IdentityResource.Status.DISABLED, 100, null).items()).hasSize(3);
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.search(IdentityResource.Status.ACTIVE, 2, first.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.search(null, 0, null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.search(null, 101, null));
		assertThatIllegalArgumentException().isThrownBy(() -> new IdentityResourcePage.Cursor(Instant.parse("2026-10-01T01:02:03.000000001Z"), UUID.randomUUID(), null));
	}

	@ParameterizedTest
	@ValueSource(strings = { "target_type = NULL", "target_id = NULL", "target_type = 'client'", "target_user_id = gen_random_uuid()", "outcome = 'failure'", "action = 'user_created', target_user_id = gen_random_uuid()" })
	void auditConstraintsRejectMissingOrMisclassifiedResourceTargets(String assignment) {
		this.resources.create("urn:orders", "Orders", AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET " + assignment).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void invalidArgumentsMissingTargetsAndStaleVersionsDoNotWrite() {
		UUID absent = UUID.randomUUID();
		assertThat(this.resources.findById(absent)).isEmpty();
		assertThatThrownBy(() -> this.resources.updateDisplayName(absent, 1, "Orders", AUDIT)).isInstanceOf(NoSuchElementException.class);
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.setEnabled(absent, 0, true, AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.create("urn:orders", "Orders", null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.resources.findById(null));
		assertThat(snapshot()).allSatisfy(rows -> assertThat(rows).isEmpty());
	}

	@Test
	void upgradingV21PreservesUserAndAuditFieldsAndDoesNotInventResourcesOrTargets() throws Exception {
		String schema = "resource_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
					.schemas(schema).defaultSchema(schema).target("21").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID user = UUID.randomUUID();
				old.sql("INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'alice', 'Alice')").param("id", user).update();
				old.sql("INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome) VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, 'user_created', 'success')")
						.param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", user).update();
				var before = old.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).single();
				var flyway = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
						.schemas(schema).defaultSchema(schema).load();
				assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
				assertThat(old.sql("SELECT (to_jsonb(a) - 'target_type' - 'target_id')::text FROM iam_security_audit a").query(String.class).single()).isEqualTo(before);
				assertThat(old.sql("SELECT count(*) FROM iam_security_audit WHERE target_type IS NOT NULL OR target_id IS NOT NULL").query(Long.class).single()).isZero();
				assertThat(old.sql("SELECT count(*) FROM iam_resource").query(Long.class).single()).isZero();
				assertThat(old.sql("SELECT username FROM iam_user WHERE id = :id").param("id", user).query(String.class).single()).isEqualTo("alice");
				assertThat(flyway.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private List<List<String>> snapshot() {
		return List.of("iam_resource", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

	private void installFault(String table, String body, boolean deferred, String operation) {
		this.jdbc.sql("CREATE FUNCTION resource_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER resource_test_fault AFTER " : "CREATE TRIGGER resource_test_fault BEFORE ")
				+ operation + " ON " + table + (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION resource_test_fault()").update();
	}

}
