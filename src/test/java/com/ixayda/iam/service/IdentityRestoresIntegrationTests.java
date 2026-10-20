package com.ixayda.iam.service;

import java.net.InetAddress;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.IdentityRestoreTestSupport;
import com.ixayda.iam.credential.ClientSecrets;
import com.ixayda.iam.model.IdentityResourceCredential;
import com.ixayda.iam.model.IdentityRestore;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityRestoreRepository;
import com.ixayda.iam.security.BrowserHttpTestSupport;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityRestoresIntegrationTests extends IdentityRestoreTestSupport {

	private static final Path TOTP_KEY = keyFile(32);
	private static final String CHECKSUM = "a".repeat(64);
	@Autowired private IdentityRestores restores;
	@Autowired private IdentityRestoreRepository restoreRepository;
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityResourceCredentials credentials;
	@Autowired private IdentityPasswordRecoveries recoveries;
	@Autowired private PostgreSQLContainer postgres;

	@DynamicPropertySource
	static void restoreProperties(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", TOTP_KEY::toString); }

	@AfterEach
	void clearRestoreStateAndFaults() {
		for (String table : List.of("iam_restore", "iam_restore_state", "iam_user", "iam_admin_bootstrap", "oauth2_registered_client", "iam_signing_key", "iam_security_audit", "iam_browser_session")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS restore_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS restore_test_fault()").update();
		this.jdbc.sql("TRUNCATE iam_restore_administrator,iam_restore_state,iam_restore,iam_signing_key_state,iam_signing_key").update();
		this.jdbc.sql("INSERT INTO iam_restore_state(singleton) VALUES(1)").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
	}

	@Test
	void quarantinesEveryIdentityCredentialGrantAndSigningKeyWhilePreservingImmutableIdentityAndAuditEvidence() {
		String resourceSecret = seedRecoverableState();
		assertThat(this.credentials.authenticate(this.resourceId.toString(), resourceSecret)).isPresent();
		var user = this.users.findById(this.userId).orElseThrow();
		var resource = this.resources.findById(this.resourceId).orElseThrow();
		var originalAudit = auditRows(this.jdbc); var operator = restoreAudit();
		this.jdbc.sql("INSERT INTO iam_user(id,username,display_name) SELECT gen_random_uuid(),'restored-'||n,'Restored' FROM generate_series(1,105) n").update();
		var restored = quarantine(this.postgres.getDatabaseName(), CHECKSUM, operator);
		assertThat(restored.snapshotAuditCount()).isEqualTo(originalAudit.size());
		assertThat(restored.snapshotLastAuditAt()).isNotNull(); assertThat(restored.snapshotLastAuditId()).isNotNull();
		assertThat(this.users.findById(this.userId).orElseThrow()).satisfies(current -> {
			assertThat(current.id()).isEqualTo(user.id()); assertThat(current.username()).isEqualTo(user.username());
			assertThat(current.createdAt()).isEqualTo(user.createdAt()); assertThat(current.status().name()).isEqualTo("DISABLED");
		});
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user WHERE status='disabled'").query(Long.class).single()).isEqualTo(106);
		assertThat(this.resources.findById(this.resourceId).orElseThrow().audience()).isEqualTo(resource.audience());
		assertThat(this.store.findById(this.sessionId)).isNull(); assertThat(this.keys.verificationKeys()).isEmpty();
		assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
		assertThat(this.protocol.findActiveById(this.clientId.toString())).isEmpty();
		assertThat(this.credentials.authenticate(this.resourceId.toString(), resourceSecret)).isEmpty();
		assertThat(this.credentials.findByResourceId(this.resourceId).orElseThrow().status()).isEqualTo(IdentityResourceCredential.Status.DISABLED);
		assertThat(auditRows(this.jdbc)).containsAll(originalAudit).hasSize(originalAudit.size() + 1);
		assertThat(this.jdbc.sql("SELECT target_id FROM iam_security_audit WHERE action='database_restore_quarantined' AND correlation_id=:id")
				.param("id", operator.correlationId()).query(UUID.class).single()).isEqualTo(restored.id());
		assertThat(quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit())).isEqualTo(restored);
		assertThat(auditRows(this.jdbc)).hasSize(originalAudit.size() + 1);
		assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId).withMessageContaining("closed");
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_admin_bootstrap SET restore_closed=false").update()).isInstanceOf(RuntimeException.class);
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_admin_bootstrap").update()).isInstanceOf(RuntimeException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_restore SET audit_gap_status='resolved'").update()).isInstanceOf(RuntimeException.class);
	}

	@Test
	void quarantinesAnEmptyInstallationWithoutInventingAnAuditWatermark() {
		this.jdbc.sql("TRUNCATE iam_user,iam_resource,oauth2_registered_client,iam_browser_session,iam_security_audit,iam_signing_key_state,iam_signing_key CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES(1)").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
		var restored = quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit());
		assertThat(restored.snapshotAuditCount()).isZero(); assertThat(restored.snapshotLastAuditAt()).isNull(); assertThat(restored.snapshotLastAuditId()).isNull();
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@Test
	void compromisesAllHistoricalKeysWithoutDecryptingDamagedPrivateMaterial() {
		var rotated = this.keys.rotate(this.signing.id(), restoreAudit());
		this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,40,get_byte(encrypted_private_key,40) # 1) WHERE id=:id")
				.param("id", rotated.id()).update();
		quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit());
		assertThat(this.jdbc.sql("SELECT status FROM iam_signing_key").query(String.class).list()).containsExactly("compromised", "compromised");
		assertThat(this.jdbc.sql("SELECT initial_key_id FROM iam_signing_key_state").query(UUID.class).single()).isEqualTo(this.signing.id());
		assertThat(this.jdbc.sql("SELECT suspension_key_id FROM iam_signing_key_state").query(UUID.class).single()).isEqualTo(rotated.id());
	}

	@Test
	void invalidAttributionAndChecksumCannotStartContainmentAndMissingStateCannotBeAssumedAvailable() {
		assertThatIllegalArgumentException().isThrownBy(() -> quarantine(this.postgres.getDatabaseName(), "invalid", restoreAudit()));
		assertThatIllegalArgumentException().isThrownBy(() -> quarantine(this.postgres.getDatabaseName(), CHECKSUM, AUDIT));
		assertThat(count("iam_restore")).isZero();
		this.jdbc.sql("TRUNCATE iam_restore_state").update();
		assertThatThrownBy(this.restores::requireAvailable).isInstanceOf(RuntimeException.class);
		assertThatThrownBy(() -> quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit())).isInstanceOf(RuntimeException.class);
		assertThat(count("iam_restore")).isZero();
	}

	@Test
	void aSnapshotTakenBeforeInitialAdministratorAndSigningSetupStillPermanentlyClosesBootstrap() {
		this.jdbc.sql("TRUNCATE iam_signing_key,iam_signing_key_state").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
		assertThat(this.administrators.candidateId()).isEmpty();
		quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit());
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
		assertThatIllegalStateException().isThrownBy(() -> this.administrators.createCandidate("new-admin", "New admin", PASSWORD, AUDIT));
		assertThat(this.users.findByUsername("new-admin")).isEmpty();
		assertThat(count("iam_signing_key")).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "iam_user", "iam_admin_bootstrap", "oauth2_registered_client", "iam_signing_key", "iam_restore_state", "iam_restore", "iam_security_audit", "iam_browser_session" })
	void storageFaultRollsBackContainmentAndDoesNotReportAQuarantinedRestore(String table) {
		seedRecoverableState(); var before = auditRows(this.jdbc);
		String operation = table.equals("iam_restore") || table.equals("iam_security_audit") ? "INSERT" : table.equals("iam_browser_session") ? "TRUNCATE" : "UPDATE";
		this.jdbc.sql("CREATE FUNCTION restore_test_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN "
				+ (operation.equals("TRUNCATE") ? "RAISE EXCEPTION ''isolated restore failure'';" : "RETURN NULL;") + " END;'").update();
		this.jdbc.sql("CREATE TRIGGER restore_test_fault BEFORE " + operation + " ON " + table + (operation.equals("TRUNCATE") ? " FOR EACH STATEMENT" : " FOR EACH ROW")
				+ " EXECUTE FUNCTION restore_test_fault()").update();
		assertThatThrownBy(() -> quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit())).isInstanceOf(RuntimeException.class);
		assertThat(this.restoreRepository.current()).isEmpty(); assertThat(count("iam_restore")).isZero();
		assertThat(this.users.findById(this.userId).orElseThrow().status().name()).isEqualTo("ACTIVE");
		assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(count("iam_refresh_history")).isPositive();
		assertThat(auditRows(this.jdbc)).isEqualTo(before);
		assertThat(this.keys.findPublicKey()).contains(this.signing);
	}

	@Test
	void alteredSnapshotEvidenceCannotBeAcceptedAsAccurate() {
		this.jdbc.sql("CREATE FUNCTION restore_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.snapshot_audit_count=NEW.snapshot_audit_count+1; RETURN NEW; END $$").update();
		this.jdbc.sql("CREATE TRIGGER restore_test_fault BEFORE INSERT ON iam_restore FOR EACH ROW EXECUTE FUNCTION restore_test_fault()").update();
		assertThatIllegalStateException().isThrownBy(() -> quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit())).withMessageContaining("evidence");
		assertThat(count("iam_restore")).isZero(); assertThat(this.users.findById(this.userId).orElseThrow().status().name()).isEqualTo("ACTIVE");
	}

	@Test
	void waitsForEvictedPoolBackendsToCloseBeforeStartingOfflineContainment() throws Exception {
		int evictedPid;
		try (var executor = Executors.newVirtualThreadPerTaskExecutor(); var held = this.dataSource.getConnection()) {
			evictedPid = JdbcClient.create(new SingleConnectionDataSource(held, true)).sql("SELECT pg_backend_pid()").query(Integer.class).single();
			var draining = executor.submit(this::evictPoolConnections);
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.dataSource.getHikariPoolMXBean().getActiveConnections() == 2);
				assertThatThrownBy(() -> draining.get(100, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
			}
			finally { held.close(); }
			draining.get(10, TimeUnit.SECONDS);
		}
		assertThat(this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=:pid)").param("pid", evictedPid).query(Boolean.class).single()).isFalse();
		assertThat(this.restores.quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit()).archiveSha256()).isEqualTo(CHECKSUM);
	}

	@Test
	void rejectsAnUnconfirmedDatabaseDifferentArchiveAmbientTransactionAndOtherConnectedClients() throws Exception {
		assertThatIllegalStateException().isThrownBy(() -> quarantine("wrong-database", CHECKSUM, restoreAudit()));
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> assertThatIllegalStateException()
				.isThrownBy(() -> this.restores.quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit()))
				.withMessageContaining("independent transaction"));
		int otherPid;
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			otherPid = JdbcClient.create(new SingleConnectionDataSource(connection, true)).sql("SELECT pg_backend_pid()").query(Integer.class).single();
			assertThat(connection.isValid(2)).isTrue();
			assertThatIllegalStateException().isThrownBy(() -> quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit()));
		}
		await().atMost(Duration.ofSeconds(5)).until(() -> !this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=:pid)")
				.param("pid", otherPid).query(Boolean.class).single());
		assertThat(count("iam_restore")).isZero();
		quarantine(this.postgres.getDatabaseName(), CHECKSUM, restoreAudit());
		assertThatIllegalStateException().isThrownBy(() -> quarantine(this.postgres.getDatabaseName(), "b".repeat(64), restoreAudit()));
	}

	@Test
	void actualPgDumpAndPgRestoreCannotReviveConsumedProofsRevokedGrantsOrCompromisedKeysAndRuntimeCannotClearQuarantine() throws Exception {
		seedRecoverableState();
		UUID recoveryUser = activeUser("recovery-target"); var proof = this.recoveries.issue(recoveryUser, AUDIT);
		String name = "restored_" + UUID.randomUUID().toString().replace("-", ""); String role = name + "_runtime"; String owner = name + "_owner";
		String archive = "/tmp/" + name + ".dump"; long started = System.nanoTime();
		var snapshotAudits = auditRows(this.jdbc);
		checked(this.postgres.execInContainer("pg_dump", "-U", this.postgres.getUsername(), "--format=custom", "--file=" + archive, this.postgres.getDatabaseName()));
		String checksum = this.postgres.execInContainer("sha256sum", archive).getStdout().split(" ")[0];
		// The live database changes after the backup. The restored snapshot contains the superseded security state.
		assertThat(this.recoveries.complete(recoveryUser, proof.token(), "meadow orbit quartz orchard 271", "internal:test", UUID.randomUUID()))
				.isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
		this.jdbc.sql("UPDATE iam_user SET status='disabled' WHERE id=:id").param("id", this.userId).update();
		this.context.getBean(IdentitySigningKeyIncidents.class).compromise(this.signing.id(), restoreAudit());
		this.jdbc.sql("CREATE ROLE " + owner + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'isolated-owner-password'").update();
		this.jdbc.sql("CREATE DATABASE " + name + " OWNER " + owner).update();
		try {
			checked(this.postgres.execInContainer("pg_restore", "-U", owner, "--single-transaction", "--no-owner", "--no-privileges", "--dbname=" + name, archive));
			String url = "jdbc:postgresql://" + this.postgres.getHost() + ":" + this.postgres.getMappedPort(5432) + "/" + name;
			JdbcClient restoredJdbc = JdbcClient.create(new DriverManagerDataSource(url, owner, "isolated-owner-password"));
			assertThat(restoredJdbc.sql("SELECT status FROM iam_user WHERE id=:id").param("id", this.userId).query(String.class).single()).isEqualTo("active");
			assertThat(restoredJdbc.sql("SELECT status FROM iam_signing_key WHERE id=:id").param("id", this.signing.id()).query(String.class).single()).isEqualTo("active");
			IdentityRestore restored;
			// No signing, authorization or factor protection keys are needed to contain an untrusted restore.
			try (var maintenance = restoredContext(url, owner, "isolated-owner-password", false, false, null)) {
				restored = maintenance.getBean(IdentityRestores.class).quarantine(name, checksum, restoreAudit());
			}
			assertThat(restored.snapshotAuditCount()).isEqualTo(snapshotAudits.size());
			assertThat(auditRows(restoredJdbc)).containsAll(snapshotAudits).hasSize(snapshotAudits.size() + 1);
			try (var maintenance = restoredContext(url, owner, "isolated-owner-password", false, false, null)) {
				assertThat(maintenance.getBean(IdentityPasswordRecoveries.class).complete(recoveryUser, proof.token(), "meadow orbit quartz orchard 271", "internal:test", UUID.randomUUID()))
						.isEqualTo(IdentityPasswordRecoveries.Result.INVALID_PROOF);
			}
			assertThat(restoredJdbc.sql("SELECT status FROM iam_signing_key WHERE id=:id").param("id", this.signing.id()).query(String.class).single()).isEqualTo("compromised");
			assertThat(restoredJdbc.sql("SELECT count(*) FROM iam_password").query(Long.class).single()).isZero();
			assertThat(restoredJdbc.sql("SELECT count(*) FROM oauth2_authorization").query(Long.class).single()).isZero();
			assertThat(restoredJdbc.sql("SELECT count(*) FROM iam_mfa_recovery_code").query(Long.class).single()).isZero();
			var hash = restoredJdbc.sql("SELECT client_secret FROM oauth2_registered_client WHERE id=:id").param("id", this.clientId.toString()).query(String.class).single();
			assertThat(new ClientSecrets().verifier().matches(this.secret, hash)).isFalse();
			this.jdbc.sql("CREATE ROLE " + role + " LOGIN NOINHERIT PASSWORD 'isolated-runtime-password'").update();
			this.postgres.copyFileToContainer(MountableFile.forHostPath(Path.of("deploy/postgresql/grant-runtime.sql")), "/tmp/restore-grant-runtime.sql");
			checked(this.postgres.execInContainer("psql", "-X", "-U", owner, "-d", name, "-v", "runtime_role=" + role, "-v", "iam_schema=public", "-f", "/tmp/restore-grant-runtime.sql"));
			try (var other = DriverManager.getConnection(url, role, "isolated-runtime-password");
					var maintenance = restoredContext(url, owner, "isolated-owner-password", false, false, null)) {
				assertThat(other.isValid(2)).isTrue();
				assertThatIllegalStateException().isThrownBy(() -> maintenance.getBean(IdentityRestores.class).quarantine(name, checksum, restoreAudit()));
			}
			try (var runtime = restoredContext(url, role, "isolated-runtime-password", false, true, null)) {
				assertThatIllegalStateException().isThrownBy(() -> runtime.getBean(IdentityRestores.class).quarantine(name, checksum, restoreAudit()));
				assertThatIllegalStateException().isThrownBy(() -> runtime.getBean(IdentityRestores.class).requireAvailable());
			}
			try (var connection = DriverManager.getConnection(url, role, "isolated-runtime-password"); var statement = connection.createStatement()) {
				for (String sql : List.of("UPDATE iam_restore_state SET current_restore_id=NULL", "DELETE FROM iam_restore", "UPDATE iam_admin_bootstrap SET restore_closed=false")) {
					assertThatThrownBy(() -> statement.execute(sql)).isInstanceOf(java.sql.SQLException.class).extracting("SQLState").isEqualTo("42501");
				}
			}
			for (boolean restricted : List.of(false, true)) {
				var servers = new AtomicInteger();
				assertThatThrownBy(() -> { try (var ignored = restoredContext(url, restricted ? role : owner, restricted ? "isolated-runtime-password" : "isolated-owner-password", true, restricted, servers)) {
					fail("Quarantine must stop Web admission");
				} }).isInstanceOf(RuntimeException.class).hasStackTraceContaining("Restored database remains quarantined");
				assertThat(servers).hasValue(0);
			}
			System.out.printf("Isolated pg_dump/pg_restore and quarantine: %.3f seconds; audit gap unresolved%n", (System.nanoTime() - started) / 1_000_000_000d);
		}
		finally {
			this.jdbc.sql("DROP DATABASE " + name + " WITH (FORCE)").update();
			this.jdbc.sql("DROP ROLE IF EXISTS " + role).update();
			this.jdbc.sql("DROP ROLE IF EXISTS " + owner).update();
			checked(this.postgres.execInContainer("rm", "-f", archive));
		}
	}

	private String seedRecoverableState() {
		String grant = code(Set.of("openid", "offline_access")); exchange(request(grant, authenticatedClient(grant)));
		String resourceSecret = this.credentials.rotateSecret(this.resourceId, 0, AUDIT).secret();
		var ctx = new TotpAuthenticationContext("deployment:test", InetAddress.getLoopbackAddress(), UUID.randomUUID());
		var factor = this.administrators.prepareCandidate(this.userId, PASSWORD, ctx).orElseThrow().enrollment().orElseThrow();
		assertThat(this.administrators.bootstrap(this.userId, factor.factorId(), PASSWORD, otp(factor), ctx)).isPresent();
		assertThat(count("iam_mfa_recovery_code")).isPositive();
		this.sessionId = browserSession(this.userId, this.authenticatedAt);
		var session = this.store.findById(this.sessionId);
		long version = new TransactionTemplate(this.transactions).execute(tx -> this.users.passwordVersion(this.userId).orElseThrow());
		session.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, version); this.store.save(session);
		return resourceSecret;
	}

	private ConfigurableApplicationContext restoredContext(String url, String username, String password, boolean web, boolean restricted, AtomicInteger servers) {
		var properties = new HashMap<String, Object>();
		properties.put("spring.datasource.url", url); properties.put("spring.datasource.username", username); properties.put("spring.datasource.password", password);
		properties.put("spring.datasource.hikari.maximum-pool-size", 1); properties.put("spring.datasource.hikari.minimum-idle", 0);
		properties.put("spring.flyway.enabled", false); properties.put("spring.main.banner-mode", "off");
		properties.put("iam.database.restricted-runtime", restricted);
		if (web) {
			properties.put("iam.signing.key-file", SIGNING_KEY.toString()); properties.put("iam.authorization.key-file", AUTHORIZATION_KEY.toString());
			properties.put("server.port", 0); properties.put("server.ssl.enabled", true);
			properties.put("server.ssl.key-store", BrowserHttpTestSupport.KEY_STORE.toUri().toString()); properties.put("server.ssl.key-store-password", "test-store-password");
			properties.put("iam.protocol.issuer", "https://iam.example"); properties.put("iam.protocol.identity-frontend-uri", "https://iam.example/identity");
		}
		var builder = new SpringApplicationBuilder(IamApplication.class).web(web ? WebApplicationType.SERVLET : WebApplicationType.NONE).properties(properties);
		if (servers != null) { builder.listeners((ApplicationListener<WebServerInitializedEvent>) event -> servers.incrementAndGet()); }
		return builder.run();
	}

	private IdentityRestore quarantine(String database, String checksum, SecurityAuditContext audit) {
		evictPoolConnections();
		return this.restores.quarantine(database, checksum, audit);
	}

	private static List<String> auditRows(JdbcClient jdbc) { return jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a ORDER BY recorded_at,id").query(String.class).list(); }
	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }
	private static SecurityAuditContext restoreAudit() { return new SecurityAuditContext("deployment:operator-1", "deployment:restore:CHANGE-123", UUID.randomUUID()); }
	private static void checked(org.testcontainers.containers.Container.ExecResult result) { assertThat(result.getExitCode()).as(result.getStderr()).isZero(); }
	private static Path keyFile(int length) {
		try {
			Path path = java.nio.file.Files.createTempFile("iam-restore-test-", ".key"); byte[] bytes = new byte[length];
			new java.security.SecureRandom().nextBytes(bytes); java.nio.file.Files.write(path, bytes); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}
	private static String otp(IdentityTotpEnrollment enrollment) {
		long step = Math.floorDiv(Instant.now().getEpochSecond(), 30); byte[] counter = java.nio.ByteBuffer.allocate(8).putLong(step).array();
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(enrollment.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		return String.format(java.util.Locale.ROOT, "%06d", (java.nio.ByteBuffer.wrap(hash).getInt(offset) & 0x7fff_ffff) % 1_000_000);
	}
}
