package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Signature;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.SigningKeySecrets;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.IdentitySigningKeyMetadata.Status;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.repository.IdentitySigningKeyRepository;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentitySigningKeysIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final Path OTHER_KEY_FILE = keyFile();

	@Autowired private IdentitySigningKeys keys;
	@Autowired private IdentitySigningKeyRepository repository;
	@Autowired private SecurityAudits audits;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.signing.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_restore_release,iam_signing_key, iam_signing_key_state, iam_security_audit").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state (singleton) VALUES (1)").update();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_signing_key", "iam_signing_key_state", "iam_security_audit")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS signing_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS signing_test_fault()").update();
	}

	@Test
	void initializesOnePersistentIdentityWithAtomicSecretFreeAuditAndUsableSigningMaterial() throws Exception {
		var key = this.keys.initialize().orElseThrow();
		assertThat(key.algorithm()).isEqualTo("RS256");
		assertThat(key.publicKey().getModulus().bitLength()).isEqualTo(3072);
		assertThat(this.keys.findPublicKey()).contains(key);
		var material = this.keys.signingMaterial();
		assertThat(material.key()).isEqualTo(key);
		var signature = Signature.getInstance("SHA256withRSA");
		byte[] message = "persistent signing verification".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		signature.initSign(material.privateKey()); signature.update(message);
		byte[] signed = signature.sign();
		signature.initVerify(key.publicKey()); signature.update(message);
		assertThat(signature.verify(signed)).isTrue();
		var stored = this.repository.findStoredKey().orElseThrow();
		assertThat(stored.encryptedPrivateKey()).isNotEqualTo(material.privateKey().getEncoded());
		assertThat(stored.protectionKeyId()).matches("[0-9a-f]{64}");
		String secret = Base64.getEncoder().encodeToString(material.privateKey().getEncoded());
		assertThat(material.toString()).contains("privateKey=REDACTED").doesNotContain(secret);
		assertThat(stored.toString()).contains("privateMaterial=REDACTED").doesNotContain(secret);
		var events = this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a").query(String.class).list();
		assertThat(events).hasSize(1).allSatisfy(event -> assertThat(event).doesNotContain(secret));
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit").query().singleRow();
		assertThat(event.get("actor")).isEqualTo("system:startup");
		assertThat(event.get("source")).isEqualTo("deployment:signing");
		assertThat(event.get("action")).isEqualTo("signing_key_initialized");
		assertThat(event.get("outcome")).isEqualTo("success");
		assertThat(event.get("target_user_id")).isNull();
		assertThat(event.get("correlation_id")).isEqualTo(key.id());
		var filter = new SecurityAuditFilter(null, null, Action.SIGNING_KEY_INITIALIZED, null, null, null, null, key.id());
		assertThat(this.audits.search(filter, 10, null).items()).hasSize(1);
	}

	@Test
	void restartAndRepeatedInitializationKeepTheIdentityCiphertextAndAuditUnchanged() throws Exception {
		var original = this.keys.initialize().orElseThrow();
		var before = snapshot();
		Path copied = Files.createTempFile("iam-signing-key-copy-", ".key");
		try {
			Files.write(copied, Files.readAllBytes(KEY_FILE));
			var restarted = withProtectionFile(copied.toString());
			assertThat(restarted.initialize()).contains(original);
			assertThat(restarted.signingMaterial().key()).isEqualTo(original);
			assertThat(this.keys.initialize()).contains(original);
			assertThat(snapshot()).isEqualTo(before);
		}
		finally { Files.deleteIfExists(copied); }
	}

	@Test
	void unconfiguredEmptyDatabaseRemainsUninitializedAndCannotSign() {
		var disabled = withProtectionFile("");
		var before = snapshot();
		assertThat(disabled.initialize()).isEmpty();
		assertThat(disabled.findPublicKey()).isEmpty();
		assertThatIllegalStateException().isThrownBy(disabled::signingMaterial);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "absent", "wrong" })
	void initializedStateRejectsAbsentOrWrongProtectionWithoutReplacingAnyMaterial(String fault) {
		var original = this.keys.initialize().orElseThrow();
		var before = snapshot();
		var unusable = withProtectionFile(fault.equals("absent") ? "" : OTHER_KEY_FILE.toString());
		assertThatIllegalStateException().isThrownBy(unusable::initialize);
		assertThatIllegalStateException().isThrownBy(unusable::signingMaterial);
		assertThat(unusable.findPublicKey()).contains(original);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void concurrentInitializersCommitExactlyOneIdentityAndAudit() throws Exception {
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(6)) {
			var futures = java.util.stream.IntStream.range(0, 6).mapToObj(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				return withProtectionFile(KEY_FILE.toString()).initialize().orElseThrow();
			})).toList();
			start.countDown();
			var expected = futures.getFirst().get(45, TimeUnit.SECONDS);
			for (var future : futures) { assertThat(future.get(45, TimeUnit.SECONDS)).isEqualTo(expected); }
		}
		assertThat(count("iam_signing_key")).isEqualTo(1);
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "key-rejected", "key-suppressed", "key-altered", "state-rejected", "state-suppressed", "audit-rejected", "audit-suppressed", "commit-rejected" })
	void storageAuditAndCommitFailuresRollBackAllInitializationStateAndPermitRetry(String fault) {
		String table = fault.startsWith("key-") ? "iam_signing_key" : fault.startsWith("state-") ? "iam_signing_key_state" : "iam_security_audit";
		String operation = fault.startsWith("state-") ? "UPDATE" : "INSERT";
		String body = fault.endsWith("suppressed") ? "RETURN NULL;" : fault.equals("key-altered")
				? "NEW.protection_key_id := repeat('0',64); RETURN NEW;" : "RAISE EXCEPTION 'test persistence failure';";
		installFault(table, operation, body, fault.equals("commit-rejected"));
		assertThatThrownBy(this.keys::initialize).isInstanceOf(RuntimeException.class);
		assertEmptyInitialization();
		removeFaults();
		assertThat(this.keys.initialize()).isPresent();
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "ciphertext", "protection-id", "public-key", "creation-time" })
	void corruptedMaterialIsRejectedWithoutReinitializingOrModifyingTheRecord(String fault) {
		this.keys.initialize();
		if (fault.equals("ciphertext")) {
			this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key = set_byte(encrypted_private_key, 30, get_byte(encrypted_private_key, 30) # 1)").update();
		}
		else if (fault.equals("protection-id")) { this.jdbc.sql("UPDATE iam_signing_key SET protection_key_id = repeat('0',64)").update(); }
		else if (fault.equals("creation-time")) { this.jdbc.sql("UPDATE iam_signing_key SET created_at = created_at + interval '1 second'").update(); }
		else {
			byte[] different = new SigningKeySecrets(KEY_FILE.toString()).generate().getPublic().getEncoded();
			this.jdbc.sql("UPDATE iam_signing_key SET public_key = :key").param("key", different).update();
		}
		var corrupted = snapshot();
		assertThatIllegalStateException().isThrownBy(this.keys::initialize);
		assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
		assertThat(snapshot()).isEqualTo(corrupted);
	}

	@Test
	void inconsistentAndMissingLifecycleRecordsCannotAuthorizeBootstrap() {
		this.keys.initialize();
		this.jdbc.sql("TRUNCATE iam_signing_key_state").update();
		var missing = snapshot();
		assertThatThrownBy(this.keys::initialize).isInstanceOf(DataAccessException.class);
		assertThat(snapshot()).isEqualTo(missing);
		this.jdbc.sql("INSERT INTO iam_signing_key_state (singleton) VALUES (1)").update();
		var inconsistent = snapshot();
		assertThatIllegalStateException().isThrownBy(this.keys::initialize).withMessage("Signing initialization state is inconsistent");
		assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
		assertThat(snapshot()).isEqualTo(inconsistent);
	}

	@Test
	void initializedMarkerWithMissingMaterialCannotCreateAReplacement() {
		this.keys.initialize();
		this.jdbc.sql("ALTER TABLE iam_signing_key_state DROP CONSTRAINT iam_signing_key_state_initial_key_id_fkey").update();
		this.jdbc.sql("ALTER TABLE iam_signing_key_state DROP CONSTRAINT iam_signing_key_state_active_key_id_fkey").update();
		try {
			this.jdbc.sql("DELETE FROM iam_signing_key").update();
			var missing = snapshot();
			assertThatIllegalStateException().isThrownBy(this.keys::initialize).withMessage("Initialized signing key is missing");
			assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
			assertThat(snapshot()).isEqualTo(missing);
		}
		finally {
			clean();
			this.jdbc.sql("ALTER TABLE iam_signing_key_state ADD CONSTRAINT iam_signing_key_state_initial_key_id_fkey FOREIGN KEY (initial_key_id) REFERENCES iam_signing_key (id) ON DELETE RESTRICT").update();
			this.jdbc.sql("ALTER TABLE iam_signing_key_state ADD CONSTRAINT iam_signing_key_state_active_key_id_fkey FOREIGN KEY (active_key_id) REFERENCES iam_signing_key (id) ON DELETE RESTRICT").update();
		}
	}

	@Test
	void databaseProtectsTheInitializationMarkerAndSingleIdentity() {
		this.keys.initialize();
		var before = snapshot();
		for (String sql : List.of("DELETE FROM iam_signing_key_state", "UPDATE iam_signing_key_state SET initial_key_id = NULL, initialized_at = NULL",
				"UPDATE iam_signing_key_state SET initialized_at = initialized_at + interval '1 second'", "DELETE FROM iam_signing_key",
				"INSERT INTO iam_signing_key (id,algorithm,public_key,encrypted_private_key,protection_key_id,created_at) SELECT gen_random_uuid(), algorithm, public_key, encrypted_private_key, protection_key_id, created_at FROM iam_signing_key")) {
			assertThatThrownBy(() -> this.jdbc.sql(sql).update()).isInstanceOf(DataIntegrityViolationException.class);
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "algorithm = 'RS512'", "public_key = ''::bytea", "public_key = decode(repeat('00',1025),'hex')",
			"encrypted_private_key = decode(repeat('01',1023),'hex')", "encrypted_private_key = set_byte(encrypted_private_key,0,2)",
			"protection_key_id = 'invalid'", "created_at = 'infinity'" })
	void databaseRejectsInvalidSigningRecords(String assignment) {
		this.keys.initialize();
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_signing_key SET " + assignment).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void publicReadsSucceedWithDatabasePermissionThatCannotReadPrivateColumns() throws Exception {
		var expected = this.keys.initialize().orElseThrow();
		String role = "signing_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT (id, algorithm, public_key, created_at, status, verification_until) ON iam_signing_key TO " + role).update();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
					var context = new AnnotationConfigApplicationContext()) {
				JdbcClient reader = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				reader.sql("SET ROLE " + role).update();
				context.registerBean(JdbcClient.class, () -> reader);
				context.register(IdentitySigningKeyRepository.class);
				context.refresh();
				var restricted = context.getBean(IdentitySigningKeyRepository.class);
				var publicOnly = new IdentitySigningKeys(restricted, new SigningKeySecrets(""), this.audits, this.transactions);
				assertThat(publicOnly.findPublicKey()).contains(expected);
				assertThatThrownBy(restricted::findStoredKey).isInstanceOf(DataAccessException.class);
			}
		}
		finally {
			this.jdbc.sql("DROP OWNED BY " + role).update();
			this.jdbc.sql("DROP ROLE " + role).update();
		}
	}

	@Test
	void neitherInitializationNorPrivateMaterialCanEscapeAnUncommittedAmbientTransaction() {
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			assertThatIllegalStateException().isThrownBy(this.keys::initialize).withMessage("Signing key access requires an independent transaction");
			assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
		});
		assertEmptyInitialization();
	}

	@Test
	void normalRotationErasesTheRetiredPrivateMaterialAndPreservesTheInitializationMarkerAndCorrelatedAudits() {
		var original = this.keys.initialize().orElseThrow();
		var marker = this.jdbc.sql("SELECT initial_key_id,initialized_at FROM iam_signing_key_state").query().singleRow();
		var audit = rotationAudit();
		var next = this.keys.rotate(original.id(), audit);
		assertThat(next.id()).isNotEqualTo(original.id());
		assertThat(next.publicKey()).isNotEqualTo(original.publicKey());
		assertThat(this.keys.initialize()).contains(next);
		assertThat(this.keys.signingMaterial().key()).isEqualTo(next);
		assertThat(this.keys.verificationKeys()).containsExactly(original, next);
		assertThat(this.jdbc.sql("SELECT initial_key_id,initialized_at FROM iam_signing_key_state").query().singleRow()).isEqualTo(marker);
		assertThat(this.keys.metadata()).filteredOn(key -> key.status() == Status.RETIRED).singleElement().satisfies(key -> {
			assertThat(key.id()).isEqualTo(original.id());
			assertThat(key.verificationUntil()).isEqualTo(key.retiredAt().plusSeconds(330));
		});
		assertThat(this.jdbc.sql("SELECT encrypted_private_key IS NULL AND protection_key_id IS NULL FROM iam_signing_key WHERE id=:id")
				.param("id", original.id()).query(Boolean.class).single()).isTrue();
		var events = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE correlation_id=:id ORDER BY action")
				.param("id", audit.correlationId()).query().listOfRows();
		assertThat(events).hasSize(2).allSatisfy(event -> {
			assertThat(event.get("actor")).isEqualTo(audit.actor());
			assertThat(event.get("source")).isEqualTo(audit.source());
			assertThat(event.get("target_type")).isEqualTo("signing_key");
			assertThat(event.get("target_user_id")).isNull();
			assertThat(event.get("outcome")).isEqualTo("success");
		});
		assertThat(events.get(0)).containsEntry("action", "signing_key_retired").containsEntry("target_id", original.id());
		assertThat(events.get(1)).containsEntry("action", "signing_key_rotated").containsEntry("target_id", next.id());
	}

	@Test
	void staleConfirmationCannotRotateAgainButAConfirmedCurrentKeyCanRotateWithAllRequiredPublicKeysRetained() {
		var original = this.keys.initialize().orElseThrow();
		var second = this.keys.rotate(original.id(), rotationAudit()); var before = snapshot();
		assertThatIllegalStateException().isThrownBy(() -> this.keys.rotate(original.id(), rotationAudit()));
		assertThat(snapshot()).isEqualTo(before);
		var third = this.keys.rotate(second.id(), rotationAudit());
		assertThat(this.keys.verificationKeys()).containsExactly(original, second, third);
		assertThat(this.keys.metadata()).filteredOn(key -> key.status() == Status.ACTIVE).singleElement().satisfies(key -> assertThat(key.id()).isEqualTo(third.id()));
		assertThat(this.jdbc.sql("SELECT revision FROM iam_signing_key_state").query(Long.class).single()).isEqualTo(3);
	}

	@Test
	void concurrentRotationsWithTheSameConfirmationCommitExactlyOnce() throws Exception {
		var original = this.keys.initialize().orElseThrow(); var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var attempts = java.util.stream.IntStream.range(0, 2).mapToObj(index -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.keys.rotate(original.id(), rotationAudit()); return true; }
				catch (IllegalStateException ex) { assertThat(ex).hasMessage("Current signing key changed"); return false; }
			})).toList(); start.countDown();
			assertThat(List.of(attempts.get(0).get(20, TimeUnit.SECONDS), attempts.get(1).get(20, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
		}
		assertThat(count("iam_signing_key")).isEqualTo(2);
		assertThat(count("iam_security_audit")).isEqualTo(3);
	}

	@ParameterizedTest
	@ValueSource(strings = { "issuance", "validation" })
	void rotationWaitsUntilExistingSigningOrOnlineValidationTransactionsCommit(String operation) throws Exception {
		var original = this.keys.initialize().orElseThrow(); var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var reader = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				if (operation.equals("issuance")) { assertThat(this.keys.lockForIssuance().key()).isEqualTo(original); }
				else { assertThat(this.keys.lockForValidation(original.id())).contains(original); }
				entered.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
			}));
			try {
				assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
				var rotation = executor.submit(() -> this.keys.rotate(original.id(), rotationAudit()));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT initial_key_id%FROM iam_signing_key_state%FOR UPDATE'").query(Long.class).single() > 0);
				assertThat(rotation.isDone()).isFalse(); assertThat(this.keys.findPublicKey()).contains(original);
				release.countDown(); reader.get(10, TimeUnit.SECONDS);
				assertThat(rotation.get(20, TimeUnit.SECONDS).id()).isNotEqualTo(original.id());
			}
			finally { release.countDown(); }
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "retire-suppressed", "retire-public-altered", "retire-time-altered", "key-suppressed", "key-altered", "state-suppressed", "state-altered", "audit-rejected", "audit-suppressed", "audit-altered", "commit-rejected" })
	void retirementReplacementActivationAndAuditsRollBackTogetherOnStorageOrCommitFaults(String failure) {
		var original = this.keys.initialize().orElseThrow(); var before = snapshot();
		String table = failure.startsWith("retire-") || failure.startsWith("key-") ? "iam_signing_key" : failure.startsWith("state-") ? "iam_signing_key_state" : "iam_security_audit";
		String operation = failure.startsWith("retire-") || failure.startsWith("state-") ? "UPDATE" : "INSERT";
		String body = failure.endsWith("suppressed") ? "RETURN NULL;" : switch (failure) {
			case "retire-public-altered" -> "NEW.public_key := set_byte(NEW.public_key,10,get_byte(NEW.public_key,10) # 1); RETURN NEW;";
			case "retire-time-altered" -> "NEW.retired_at := NEW.retired_at+interval '1 second'; NEW.verification_until := NEW.verification_until+interval '1 second'; RETURN NEW;";
			case "key-altered" -> "NEW.protection_key_id := repeat('0',64); RETURN NEW;";
			case "state-altered" -> "NEW.active_key_id := OLD.active_key_id; NEW.active_key_created_at := OLD.active_key_created_at; RETURN NEW;";
			case "audit-altered" -> "NEW.target_id := gen_random_uuid(); RETURN NEW;";
			default -> "RAISE EXCEPTION 'isolated rotation storage failure';";
		};
		installFault(table, operation, body, failure.equals("commit-rejected"));
		assertThatThrownBy(() -> this.keys.rotate(original.id(), rotationAudit())).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before); removeFaults();
		assertThat(this.keys.rotate(original.id(), rotationAudit()).id()).isNotEqualTo(original.id());
	}

	@ParameterizedTest
	@ValueSource(strings = { "absent", "wrong", "ciphertext", "ambient" })
	void rotationCannotReplaceAnUnusableCurrentKeyOrEscapeAnUncommittedCaller(String failure) {
		var original = this.keys.initialize().orElseThrow();
		if (failure.equals("ciphertext")) { this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1)").update(); }
		var before = snapshot();
		var candidate = failure.equals("absent") || failure.equals("wrong") ? withProtectionFile(failure.equals("absent") ? "" : OTHER_KEY_FILE.toString()) : this.keys;
		if (failure.equals("ambient")) {
			new TransactionTemplate(this.transactions).executeWithoutResult(tx -> assertThatIllegalStateException().isThrownBy(() -> candidate.rotate(original.id(), rotationAudit())));
		}
		else { assertThatIllegalStateException().isThrownBy(() -> candidate.rotate(original.id(), rotationAudit())); }
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void expiredRetiredKeysLeaveBothPublicVerificationPathsWhileTheCurrentKeyAndInitializationRemainStable() {
		var original = this.keys.initialize().orElseThrow(); var current = this.keys.rotate(original.id(), rotationAudit());
		// Move this public-only history into the past instead of waiting 330 real seconds.
		this.jdbc.sql("""
				WITH moment AS MATERIALIZED (SELECT clock_timestamp() AS now)
				UPDATE iam_signing_key SET created_at=moment.now-interval '10 minutes',retired_at=moment.now-interval '331 seconds',verification_until=moment.now-interval '1 second'
				FROM moment WHERE id=:id
				""").param("id", original.id()).update();
		assertThat(this.keys.verificationKeys()).containsExactly(current);
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThat(this.keys.lockForValidation(original.id())).isEmpty();
			assertThat(this.keys.lockForValidation(current.id())).contains(current);
		});
		assertThat(this.keys.initialize()).contains(current);
		assertThat(this.keys.metadata()).hasSize(2);
	}

	@ParameterizedTest
	@ValueSource(strings = { "status='retired'", "status='unknown'", "encrypted_private_key=NULL", "protection_key_id=NULL", "retired_at=clock_timestamp()", "verification_until=clock_timestamp()" })
	void databaseRequiresCompleteActiveOrRetiredStates(String assignment) {
		this.keys.initialize(); var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_signing_key SET " + assignment).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradePreservesExistingIdentityCiphertextInitializationAndAuditWithoutRotating() throws Exception {
		var original = this.keys.initialize().orElseThrow();
		String schema = "signing_rotation_upgrade_" + UUID.randomUUID().toString().replace("-", ""); this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("38").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema); var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				copyRows(old, "iam_signing_key");
				old.sql("UPDATE iam_signing_key_state SET initial_key_id=:id, initialized_at=(SELECT created_at FROM iam_signing_key WHERE id=:id)").param("id", original.id()).update();
				copyRows(old, "iam_security_audit");
				var before = old.sql("SELECT to_jsonb(s)::text FROM iam_signing_key s").query(String.class).single();
				var audit = old.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list();
				var migration = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("39").load();
				assertThat(migration.migrate().migrationsExecuted).isEqualTo(1);
				assertThat(old.sql("SELECT (to_jsonb(s)-'status'-'retired_at'-'verification_until')::text FROM iam_signing_key s").query(String.class).single()).isEqualTo(before);
				assertThat(old.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list()).isEqualTo(audit);
				assertThat(old.sql("SELECT active_key_id=initial_key_id AND active_key_created_at=initialized_at AND revision=1 FROM iam_signing_key_state").query(Boolean.class).single()).isTrue();
				assertThat(migration.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private static SecurityAuditContext rotationAudit() { return new SecurityAuditContext("deployment:operator-1", "deployment:signing-rotation:CHANGE-123", UUID.randomUUID()); }

	private IdentitySigningKeys withProtectionFile(String file) {
		return new IdentitySigningKeys(this.repository, new SigningKeySecrets(file), this.audits, this.transactions);
	}

	private void assertEmptyInitialization() {
		assertThat(count("iam_signing_key")).isZero();
		assertThat(count("iam_security_audit")).isZero();
		assertThat(this.jdbc.sql("SELECT initial_key_id IS NULL AND initialized_at IS NULL FROM iam_signing_key_state WHERE singleton = 1").query(Boolean.class).single()).isTrue();
	}

	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }

	private List<List<String>> snapshot() {
		return List.of("iam_signing_key", "iam_signing_key_state", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT row_to_json(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

	private void installFault(String table, String operation, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION signing_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END $$").update();
		String declaration = deferred ? "CREATE CONSTRAINT TRIGGER signing_test_fault AFTER " + operation + " ON " + table + " DEFERRABLE INITIALLY DEFERRED"
				: "CREATE TRIGGER signing_test_fault BEFORE " + operation + " ON " + table;
		this.jdbc.sql(declaration + " FOR EACH ROW EXECUTE FUNCTION signing_test_fault()").update();
	}

	private static Path keyFile() {
		try {
			Path file = Files.createTempFile("iam-signing-test-", ".key");
			byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
			Files.write(file, bytes); file.toFile().deleteOnExit(); return file;
		}
		catch (java.io.IOException ex) { throw new java.io.UncheckedIOException(ex); }
	}

}
