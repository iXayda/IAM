package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityResourceCredential;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;

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
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityResourceCredentialsIntegrationTests {

	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:resource-test", "internal:resource", UUID.randomUUID());
	@Autowired private IdentityResourceCredentials credentials;
	@Autowired private IdentityResources resources;
	@Autowired private SecurityAudits audits;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private UUID resourceId;

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_resource_credential", "iam_security_audit")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS resource_credential_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS resource_credential_test_fault()").update();
	}

	@Test
	void generatedSecretIsDeliveredOnceAndNeitherQueriesNorAuditExposeItOrItsHash() {
		assertThat(this.credentials.findByResourceId(this.resourceId)).isEmpty();
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		assertThat(issued.secret()).matches("[A-Za-z0-9_-]{43}");
		assertThat(issued.credential().version()).isEqualTo(1);
		assertThat(issued.credential().status()).isEqualTo(IdentityResourceCredential.Status.ACTIVE);
		assertThat(this.credentials.findByResourceId(this.resourceId)).contains(issued.credential());
		String hash = this.jdbc.sql("SELECT secret_hash FROM iam_resource_credential").query(String.class).single();
		assertThat(hash).startsWith("{argon2}$argon2id$v=19$m=19456,t=2,p=1$");
		var snapshot = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		assertThat(snapshot.resource().id()).isEqualTo(this.resourceId);
		assertThat(snapshot.credential()).isEqualTo(issued.credential());
		assertThat(snapshot.toString()).isEqualTo("ResourceCredentialSnapshot[REDACTED]");
		assertThat(issued.toString()).isEqualTo("IdentityResourceSecret[REDACTED]");
		assertThat(issued.credential().toString()).doesNotContain(hash, issued.secret());
		assertThat(this.jdbc.sql("SELECT to_jsonb(r)::text FROM iam_resource_credential r").query(String.class).single()).doesNotContain(issued.secret());
		assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list().toString()).doesNotContain(hash, issued.secret());
		assertThat(this.jdbc.sql("SELECT actor,source,target_user_id,target_type,target_id,correlation_id,outcome FROM iam_security_audit WHERE action='resource_credential_issued'")
				.query().singleRow()).containsEntry("actor", AUDIT.actor()).containsEntry("source", AUDIT.source()).containsEntry("target_user_id", null)
				.containsEntry("target_type", "resource").containsEntry("target_id", this.resourceId).containsEntry("correlation_id", AUDIT.correlationId()).containsEntry("outcome", "success");
	}

	@Test
	void rotationAndDisableInvalidateOldSecretsAndSnapshotsWithoutChangingTheResource() {
		var resource = this.resources.findById(this.resourceId).orElseThrow();
		var first = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var old = this.credentials.authenticate(this.resourceId.toString(), first.secret()).orElseThrow();
		assertThat(recheck(old)).contains(old);
		var disabled = this.credentials.disable(this.resourceId, 1, AUDIT);
		assertThat(disabled.version()).isEqualTo(2);
		assertThat(disabled.createdAt()).isEqualTo(first.credential().createdAt());
		assertThat(disabled.rotatedAt()).isEqualTo(first.credential().rotatedAt());
		assertThat(this.credentials.authenticate(this.resourceId.toString(), first.secret())).isEmpty();
		assertThat(recheck(old)).isEmpty();
		var before = snapshot();
		assertThat(this.credentials.disable(this.resourceId, 2, AUDIT)).isEqualTo(disabled);
		assertThat(snapshot()).isEqualTo(before);
		var replacement = this.credentials.rotateSecret(this.resourceId, 2, AUDIT);
		assertThat(replacement.secret()).isNotEqualTo(first.secret());
		assertThat(replacement.credential().version()).isEqualTo(3);
		assertThat(replacement.credential().status()).isEqualTo(IdentityResourceCredential.Status.ACTIVE);
		assertThat(replacement.credential().createdAt()).isEqualTo(first.credential().createdAt());
		assertThat(replacement.credential().rotatedAt()).isAfterOrEqualTo(disabled.updatedAt());
		assertThat(this.credentials.authenticate(this.resourceId.toString(), first.secret())).isEmpty();
		assertThat(this.credentials.authenticate(this.resourceId.toString(), replacement.secret())).isPresent();
		assertThat(recheck(old)).isEmpty();
		assertThat(this.resources.findById(this.resourceId)).contains(resource);
		assertThat(this.jdbc.sql("SELECT action FROM iam_security_audit WHERE action LIKE 'resource_credential_%' ORDER BY recorded_at,id").query(String.class).list())
				.containsExactly("resource_credential_issued", "resource_credential_disabled", "resource_credential_rotated");
	}

	@Test
	void resourceDisablingIsIndependentFromExplicitCredentialDisable() {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var authenticated = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		var before = snapshot();
		assertThat(this.credentials.authenticate(this.resourceId.toString(), issued.secret())).isEmpty();
		assertThat(recheck(authenticated)).isEmpty();
		assertThatThrownBy(() -> this.credentials.rotateSecret(this.resourceId, 1, AUDIT)).isInstanceOf(IdentityResourceCredentials.ResourceCredentialNotAllowedException.class);
		assertThat(snapshot()).isEqualTo(before);
		this.credentials.disable(this.resourceId, 1, AUDIT);
		this.resources.setEnabled(this.resourceId, 2, true, AUDIT);
		assertThat(this.credentials.authenticate(this.resourceId.toString(), issued.secret())).isEmpty();
		assertThat(this.credentials.rotateSecret(this.resourceId, 2, AUDIT).credential().status()).isEqualTo(IdentityResourceCredential.Status.ACTIVE);
	}

	@Test
	void temporaryResourceDisablePreservesActiveCredentialButInvalidatesOldResourceSnapshots() {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var authenticated = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		this.resources.setEnabled(this.resourceId, 2, true, AUDIT);
		assertThat(this.credentials.findByResourceId(this.resourceId)).contains(issued.credential());
		assertThat(this.credentials.authenticate(this.resourceId.toString(), issued.secret())).isPresent();
		assertThat(recheck(authenticated)).isEmpty();
	}

	@Test
	void unsupportedStoredHashEncodingFailsClosedBeforeArgon2Verification() {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		this.jdbc.sql("UPDATE iam_resource_credential SET secret_hash='{argon2}$argon2id$v=19$m=19456,t=2,p=1$' || repeat('B',22) || '$' || repeat('B',43),version=2").update();
		assertThatThrownBy(() -> this.credentials.authenticate(this.resourceId.toString(), issued.secret()))
				.isInstanceOf(IllegalStateException.class).hasMessage("Resource credential hash is invalid");
	}

	@Test
	void malformedUnknownAndCrossResourceCredentialsCannotAuthenticate() {
		UUID resourceId = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
		this.jdbc.sql("INSERT INTO iam_resource (id, audience, display_name) VALUES (:id, 'urn:canonical-id', 'Canonical ID')")
				.param("id", resourceId).update();
		var issued = this.credentials.rotateSecret(resourceId, 0, AUDIT);
		assertThat(this.credentials.authenticate(resourceId.toString(), issued.secret())).isPresent();
		UUID other = this.resources.create("urn:other", "Other", AUDIT).id();
		var otherSecret = this.credentials.rotateSecret(other, 0, AUDIT);
		var before = snapshot();
		for (String id : List.of("", "x", UUID.randomUUID().toString(), resourceId.toString().toUpperCase(java.util.Locale.ROOT), " " + resourceId)) {
			assertThat(this.credentials.authenticate(id, issued.secret())).isEmpty();
		}
		assertThat(this.credentials.authenticate(null, issued.secret())).isEmpty();
		assertThat(this.credentials.authenticate(resourceId.toString(), null)).isEmpty();
		for (String secret : List.of("", "bad", "x".repeat(44), "A".repeat(42) + "B", " " + issued.secret(), otherSecret.secret())) {
			assertThat(this.credentials.authenticate(resourceId.toString(), secret)).isEmpty();
		}
		assertThat(this.credentials.authenticate(other.toString(), issued.secret())).isEmpty();
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void missingInputsStaleVersionsAndMissingParentsCannotWrite() {
		var before = snapshot();
		assertThatIllegalArgumentException().isThrownBy(() -> this.credentials.rotateSecret(null, 0, AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.credentials.rotateSecret(this.resourceId, -1, AUDIT));
		assertThatIllegalArgumentException().isThrownBy(() -> this.credentials.rotateSecret(this.resourceId, 0, null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.credentials.findByResourceId(null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.credentials.disable(this.resourceId, 0, AUDIT));
		assertThatThrownBy(() -> this.credentials.rotateSecret(UUID.randomUUID(), 0, AUDIT)).isInstanceOf(java.util.NoSuchElementException.class);
		assertThatThrownBy(() -> this.credentials.disable(this.resourceId, 1, AUDIT)).isInstanceOf(java.util.NoSuchElementException.class);
		assertThatThrownBy(() -> this.credentials.rotateSecret(this.resourceId, 1, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(before);
		this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		before = snapshot();
		assertThatThrownBy(() -> this.credentials.rotateSecret(this.resourceId, 0, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThatThrownBy(() -> this.credentials.disable(this.resourceId, 2, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void validationAndLifecycleRequireWritableReadCommittedTransactions() {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var authenticated = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		assertThatThrownBy(() -> this.credentials.lockForValidation(authenticated)).isInstanceOf(IllegalTransactionStateException.class);
		var readOnly = new TransactionTemplate(this.transactions); readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(tx -> this.credentials.lockForValidation(authenticated))).isInstanceOf(IllegalStateException.class);
		for (int isolation : List.of(TransactionDefinition.ISOLATION_REPEATABLE_READ, TransactionDefinition.ISOLATION_SERIALIZABLE)) {
			var transaction = new TransactionTemplate(this.transactions); transaction.setIsolationLevel(isolation);
			assertThatThrownBy(() -> transaction.execute(tx -> this.credentials.lockForValidation(authenticated))).isInstanceOf(IllegalStateException.class);
			assertThatThrownBy(() -> transaction.execute(tx -> this.credentials.rotateSecret(this.resourceId, 1, AUDIT))).isInstanceOf(IllegalStateException.class);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue", "rotate", "disable" })
	void concurrentChangesOfOneVersionHaveExactlyOneWinner(String operation) throws Exception {
		long version = operation.equals("issue") ? 0 : this.credentials.rotateSecret(this.resourceId, 0, AUDIT).credential().version();
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var futures = new ArrayList<java.util.concurrent.Future<Boolean>>();
			for (int i = 0; i < 2; i++) {
				futures.add(executor.submit(() -> {
					assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
					try {
						if (operation.equals("disable")) { this.credentials.disable(this.resourceId, version, AUDIT); }
						else { this.credentials.rotateSecret(this.resourceId, version, AUDIT); }
						return true;
					}
					catch (OptimisticLockingFailureException ex) { return false; }
				}));
			}
			start.countDown();
			var outcomes = new ArrayList<Boolean>();
			for (var future : futures) { outcomes.add(future.get(20, TimeUnit.SECONDS)); }
			assertThat(outcomes).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.credentials.findByResourceId(this.resourceId).orElseThrow().version()).isEqualTo(version + 1);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action=:action").param("action", "resource_credential_" + (operation.equals("issue") ? "issued" : operation.equals("rotate") ? "rotated" : "disabled"))
				.query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void validatorWaitingForARotationRechecksTheCommittedVersion() throws Exception {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var authenticated = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var rotating = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.credentials.rotateSecret(this.resourceId, 1, AUDIT); locked.countDown(); awaitRelease(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var validating = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> this.credentials.lockForValidation(authenticated)));
			try { awaitParentWait(); } finally { release.countDown(); }
			rotating.get(10, TimeUnit.SECONDS);
			assertThat(validating.get(10, TimeUnit.SECONDS)).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "rotate", "disable", "resource-disabled" })
	void validationRetainsTheParentLockThroughItsOuterCommit(String mutation) throws Exception {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var authenticated = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var validating = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				assertThat(this.credentials.lockForValidation(authenticated)).contains(authenticated); locked.countDown(); awaitRelease(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var writing = executor.submit(() -> {
				switch (mutation) {
					case "rotate" -> this.credentials.rotateSecret(this.resourceId, 1, AUDIT);
					case "disable" -> this.credentials.disable(this.resourceId, 1, AUDIT);
					default -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
				}
			});
			try { awaitParentWait(); assertThat(writing.isDone()).isFalse(); } finally { release.countDown(); }
			validating.get(10, TimeUnit.SECONDS); writing.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.credentials.authenticate(this.resourceId.toString(), issued.secret())).isEmpty();
		assertThat(recheck(authenticated)).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue-audit", "rotate-audit", "disable-audit", "issue-audit-suppressed", "rotate-audit-altered", "issue-deferred", "rotate-deferred", "disable-deferred", "issue-suppressed", "rotate-suppressed", "disable-suppressed", "issue-altered", "rotate-altered", "disable-altered" })
	void writeAuditAndCommitFaultsCannotPublishPartialChanges(String operation) {
		if (!operation.startsWith("issue")) { this.credentials.rotateSecret(this.resourceId, 0, AUDIT); }
		String table = operation.contains("audit") || operation.endsWith("deferred") ? "iam_security_audit" : "iam_resource_credential";
		String change = table.equals("iam_security_audit") || operation.startsWith("issue") ? "INSERT" : "UPDATE";
		String body = operation.endsWith("suppressed") ? "RETURN NULL;" : operation.endsWith("altered")
				? (table.equals("iam_security_audit") ? "NEW.actor='system:altered'; RETURN NEW;" : "NEW.updated_at=NEW.updated_at + INTERVAL '1 second'; RETURN NEW;")
				: "RAISE EXCEPTION 'test resource credential failure';";
		boolean deferred = operation.endsWith("deferred");
		var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION resource_credential_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER " : "CREATE TRIGGER ") + "resource_credential_test_fault " + (deferred ? "AFTER " : "BEFORE ") + change + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION resource_credential_test_fault()").update();
		assertThatThrownBy(() -> {
			if (operation.startsWith("disable")) { this.credentials.disable(this.resourceId, 1, AUDIT); }
			else { this.credentials.rotateSecret(this.resourceId, operation.startsWith("issue") ? 0 : 1, AUDIT); }
		}).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void outerRollbackDoesNotLeaveACredentialOrSuccessAudit() {
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> { this.credentials.rotateSecret(this.resourceId, 0, AUDIT); tx.setRollbackOnly(); });
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "DELETE FROM iam_resource_credential", "UPDATE iam_resource_credential SET version=version", "UPDATE iam_resource_credential SET version=version+2", "UPDATE iam_resource_credential SET resource_id=gen_random_uuid(),version=version+1", "UPDATE iam_resource_credential SET created_at=created_at-INTERVAL '1 second',version=version+1", "UPDATE iam_resource_credential SET secret_hash='plaintext',version=version+1", "UPDATE iam_resource_credential SET updated_at='infinity',version=version+1", "UPDATE iam_resource_credential SET status='active',version=version+1" })
	void databaseGuardsPreventIdentityReuseInvalidHashesAndReenablingAnOldSecret(String sql) {
		this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		this.credentials.disable(this.resourceId, 1, AUDIT);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql(sql).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "target_user_id=gen_random_uuid()", "target_type=NULL", "target_id=NULL", "target_type='client'", "outcome='failure'" })
	void lifecycleAuditAlwaysTargetsTheResourceAsASuccessfulMutation(String assignment) {
		this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		this.credentials.rotateSecret(this.resourceId, 1, AUDIT);
		this.credentials.disable(this.resourceId, 2, AUDIT);
		var before = snapshot();
		for (String action : List.of("issued", "rotated", "disabled")) {
			assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET " + assignment + " WHERE action=:action")
					.param("action", "resource_credential_" + action).update()).isInstanceOf(DataIntegrityViolationException.class);
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradePreservesExistingAuditsAndResourcesWithoutCreatingValidationIdentities() throws Exception {
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			this.audits.recordFailure(Action.USER_INFO_REJECTED, null, AUDIT);
			this.audits.recordTargetSuccess(Action.AUTHORIZATION_REVOKED, UUID.randomUUID(), new SecurityAuditTarget(SecurityAuditTarget.Type.AUTHORIZATION, UUID.randomUUID()), AUDIT);
		});
		String schema = "resource_credential_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("33").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : List.of("iam_resource", "iam_security_audit")) { copyRows(old, table); }
				var before = List.of("iam_resource", "iam_security_audit").stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				var migration = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("34").load();
				assertThat(migration.migrate().migrationsExecuted).isEqualTo(1);
				assertThat(List.of("iam_resource", "iam_security_audit").stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList()).isEqualTo(before);
				assertThat(old.sql("SELECT count(*) FROM iam_resource_credential").query(Long.class).single()).isZero();
				assertThat(migration.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private java.util.Optional<IdentityResourceCredentials.Snapshot> recheck(IdentityResourceCredentials.Snapshot expected) {
		return new TransactionTemplate(this.transactions).execute(tx -> this.credentials.lockForValidation(expected));
	}

	private List<List<String>> snapshot() {
		return List.of("iam_resource_credential", "iam_resource", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

	private void awaitParentWait() {
		await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_resource WHERE id%'").query(Long.class).single() > 0);
	}

	private static void awaitRelease(CountDownLatch release) {
		try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
	}

}
