package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Signature;
import java.sql.DriverManager;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.SigningKeySecrets;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.repository.IdentitySigningKeyRepository;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
		this.jdbc.sql("TRUNCATE iam_signing_key, iam_signing_key_state, iam_security_audit").update();
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
		}
	}

	@Test
	void databaseProtectsTheInitializationMarkerAndSingleIdentity() {
		this.keys.initialize();
		var before = snapshot();
		for (String sql : List.of("DELETE FROM iam_signing_key_state", "UPDATE iam_signing_key_state SET initial_key_id = NULL, initialized_at = NULL",
				"UPDATE iam_signing_key_state SET initialized_at = initialized_at + interval '1 second'", "DELETE FROM iam_signing_key",
				"INSERT INTO iam_signing_key SELECT gen_random_uuid(), algorithm, public_key, encrypted_private_key, protection_key_id, created_at FROM iam_signing_key")) {
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
			this.jdbc.sql("GRANT SELECT (id, algorithm, public_key, created_at) ON iam_signing_key TO " + role).update();
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
