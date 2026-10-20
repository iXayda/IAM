package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.IdentityRestoreTestSupport;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityRestoreRelease;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.repository.IdentityRestoreReleaseRepository;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;

class IdentityRestoreReleasesIntegrationTests extends IdentityRestoreTestSupport {

	private static final Path TOTP_KEY = keyFile();
	private static final String NEW_PASSWORD = "violet lighthouse cedar river 827";
	private static final SecurityAuditContext QUARANTINE = new SecurityAuditContext("deployment:operator-1", "deployment:restore:CHANGE-122", UUID.randomUUID());
	private static final SecurityAuditContext RECOVERY = new SecurityAuditContext("deployment:operator-1", "deployment:restore-admin:CHANGE-123", UUID.randomUUID());
	private static final SecurityAuditContext RELEASE = new SecurityAuditContext("deployment:operator-2", "deployment:restore-release:CHANGE-124", UUID.randomUUID());
	@Autowired private IdentityRestoreReleases releases;
	@Autowired private IdentityRestoreAdministrators recovery;
	@Autowired private IdentityRestores restores;
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityRestoreReleaseRepository repository;
	private UUID restoreId;
	private String database;
	private IdentityTotpEnrollment enrollment;
	private String enrollmentCode;
	private IdentitySigningKey freshKey;

	@DynamicPropertySource
	static void factorKey(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", TOTP_KEY::toString); }

	@BeforeEach
	void establishNewOfflineAdministratorAndSigningIdentity() {
		this.database = this.restores.databaseName(); evictPoolConnections();
		this.restoreId = this.restores.quarantine(this.database, "a".repeat(64), QUARANTINE).id();
		this.enrollment = TotpTestSupport.distinctEnrollment(() -> {
			evictPoolConnections();
			return this.recovery.prepare(this.database, this.restoreId, this.userId, NEW_PASSWORD, RECOVERY);
		});
		this.enrollmentCode = referenceTotp(this.enrollment, step());
		evictPoolConnections(); assertThat(this.recovery.complete(this.database, this.restoreId, this.userId, this.enrollment.factorId(), NEW_PASSWORD, this.enrollmentCode, RECOVERY)).isPresent();
		this.freshKey = this.keys.recover(this.signing.id(), RELEASE);
	}

	@AfterEach
	void removeRecoveryStateAndStorageFaults() {
		for (String table : List.of("iam_restore_release", "iam_security_audit")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS restore_release_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS restore_release_test_fault()").update();
		this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT IF EXISTS restore_release_audit_fault").update();
		this.jdbc.sql("TRUNCATE iam_restore_release,iam_restore_administrator,iam_restore_state,iam_restore,iam_signing_key_state,iam_signing_key").update();
		this.jdbc.sql("INSERT INTO iam_restore_state(singleton) VALUES(1)").update(); this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
	}

	@Test
	void independentlyAuthorizesReleaseWithNewPasswordFreshFactorAndKeyAndRetainsAllOtherContainment() {
		assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
		String code = freshTotp(this.enrollment);
		var released = release(NEW_PASSWORD, code).orElseThrow();
		this.restores.requireAvailable(); this.context.getBean(IdentityReadiness.class).requireReady();
		assertThat(released.restoreId()).isEqualTo(this.restoreId); assertThat(released.userId()).isEqualTo(this.userId);
		assertThat(released.factorId()).isEqualTo(this.enrollment.factorId()); assertThat(released.signingKeyId()).isEqualTo(this.freshKey.id());
		assertThat(count("iam_browser_session")).isZero(); assertThat(count("oauth2_authorization")).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_user WHERE status<>'disabled' AND id<>:user").param("user", this.userId).query(Long.class).single()).isZero();
		for (String table : List.of("iam_resource", "iam_resource_role", "iam_client")) {
			assertThat(this.jdbc.sql("SELECT count(*) FROM " + table + " WHERE status<>'disabled'").query(Long.class).single()).isZero();
		}
		assertThat(this.jdbc.sql("SELECT audit_gap_status FROM iam_restore").query(String.class).single()).isEqualTo("unresolved");
		assertThat(this.jdbc.sql("SELECT current_restore_id FROM iam_restore_state").query(UUID.class).single()).isEqualTo(this.restoreId);
		var audit = this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a WHERE action='database_restore_released'").query(String.class).single();
		assertThat(audit).contains(this.restoreId.toString(), this.userId.toString(), RELEASE.actor(), RELEASE.correlationId().toString()).doesNotContain(NEW_PASSWORD, this.enrollment.secret());
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
		assertThatIllegalStateException().isThrownBy(() -> release(NEW_PASSWORD, code));
		assertThat(this.repository.find(this.restoreId)).contains(released);
		for (String sql : List.of("UPDATE iam_restore_release SET released_at=clock_timestamp()", "DELETE FROM iam_restore_release", "UPDATE iam_restore_state SET current_restore_id=NULL")) {
			assertThatThrownBy(() -> this.jdbc.sql(sql).update()).isInstanceOf(RuntimeException.class);
		}
	}

	@Test
	void wrongPasswordMalformedAndReplayedFactorsCannotReleaseOrCreateASession() {
		assertThat(release(PASSWORD, freshTotp(this.enrollment))).isEmpty();
		assertThat(release(NEW_PASSWORD, "invalid")).isEmpty();
		assertThat(release(NEW_PASSWORD, this.enrollmentCode)).isEmpty();
		assertThat(count("iam_restore_release")).isZero(); assertThat(count("iam_browser_session")).isZero();
		assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
		assertThat(release(NEW_PASSWORD, freshTotp(this.enrollment))).isPresent();
	}

	@Test
	void failedAuthenticationsShareTheFactorBudgetAndBlockEvenACorrectCode() {
		for (int attempt = 0; attempt < 5; attempt++) { assertThat(release(NEW_PASSWORD, "invalid")).isEmpty(); }
		assertThat(release(NEW_PASSWORD, freshTotp(this.enrollment))).isEmpty();
		assertThat(count("iam_restore_release")).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='restore_release_throttled'").query(Long.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "iam_restore_release", "iam_security_audit" })
	void suppressedSuccessWritesRollBackReleaseAndFactorConsumptionAndPermitARealRetry(String table) {
		this.jdbc.sql("CREATE FUNCTION restore_release_test_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END;'").update();
		this.jdbc.sql("CREATE TRIGGER restore_release_test_fault BEFORE INSERT ON " + table + " FOR EACH ROW EXECUTE FUNCTION restore_release_test_fault()").update();
		String code = freshTotp(this.enrollment);
		assertThatThrownBy(() -> release(NEW_PASSWORD, code)).isInstanceOf(RuntimeException.class);
		assertThat(count("iam_restore_release")).isZero(); assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
		this.jdbc.sql("DROP TRIGGER restore_release_test_fault ON " + table).update();
		assertThat(release(NEW_PASSWORD, code)).isPresent();
	}

	@Test
	void alteredReleaseEvidenceCannotApproveAMismatchedFactorKeyOrEarlierTime() {
		String code = freshTotp(this.enrollment);
		for (String mutation : List.of("NEW.factor_id=gen_random_uuid();", "NEW.signing_key_id='" + this.signing.id() + "'::uuid;", "NEW.released_at='2000-01-01'::timestamptz;")) {
			this.jdbc.sql("CREATE OR REPLACE FUNCTION restore_release_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + mutation + " RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER restore_release_test_fault BEFORE INSERT ON iam_restore_release FOR EACH ROW EXECUTE FUNCTION restore_release_test_fault()").update();
			assertThatThrownBy(() -> release(NEW_PASSWORD, code)).isInstanceOf(RuntimeException.class);
			assertThat(count("iam_restore_release")).isZero(); assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
			this.jdbc.sql("DROP TRIGGER restore_release_test_fault ON iam_restore_release").update();
		}
		assertThat(release(NEW_PASSWORD, code)).isPresent();
	}

	@Test
	void finalAuditFailureRollsBackTheReleaseRecordAndAllowsTheSameFreshCodeToBeRetried() {
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT restore_release_audit_fault CHECK(action<>'database_restore_released') NOT VALID").update();
		String code = freshTotp(this.enrollment);
		assertThatThrownBy(() -> release(NEW_PASSWORD, code)).isInstanceOf(RuntimeException.class);
		assertThat(count("iam_restore_release")).isZero();
		this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT restore_release_audit_fault").update();
		assertThat(release(NEW_PASSWORD, code)).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "resource", "role", "client", "subject", "session", "pending-setup", "missing-administrator", "suspended-signing" })
	void inconsistentRemainingTrustOrUnavailableSigningCannotBeReleased(String fault) {
		String code = freshTotp(this.enrollment);
		switch (fault) {
			case "resource" -> this.jdbc.sql("UPDATE iam_resource SET status='active',version=version+1,updated_at=clock_timestamp() WHERE id=:id").param("id", this.resourceId).update();
			case "role" -> this.jdbc.sql("UPDATE iam_resource_role SET status='active',version=version+1,updated_at=clock_timestamp() WHERE id=:id").param("id", this.roleId).update();
			case "client" -> this.jdbc.sql("UPDATE iam_client SET status='active',version=version+1,updated_at=clock_timestamp() WHERE id=:id").param("id", this.clientId.toString()).update();
			case "subject" -> this.users.create("unexpected-subject", "Unexpected", AUDIT);
			case "session" -> browserSession(this.userId, System.currentTimeMillis());
			case "pending-setup" -> this.jdbc.sql("UPDATE iam_user_setup SET status='issued',finished_at=NULL").update();
			case "missing-administrator" -> this.jdbc.sql("DELETE FROM iam_administrator").update();
			case "suspended-signing" -> this.context.getBean(IdentitySigningKeyIncidents.class).compromise(this.freshKey.id(), RELEASE);
		}
		assertThatThrownBy(() -> release(NEW_PASSWORD, code)).isInstanceOf(RuntimeException.class);
		assertThat(count("iam_restore_release")).isZero(); assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
	}

	@Test
	void oldReleaseAndAdministratorEvidenceCannotAdmitANewlyRestoredArchive() {
		assertThat(release(NEW_PASSWORD, freshTotp(this.enrollment))).isPresent();
		var original = this.repository.find(this.restoreId).orElseThrow();
		evictPoolConnections(); var next = this.restores.quarantine(this.database, "b".repeat(64), QUARANTINE);
		assertThat(next.id()).isNotEqualTo(this.restoreId); assertThat(count("iam_restore")).isEqualTo(2);
		assertThat(this.repository.find(this.restoreId)).contains(original); assertThat(count("iam_restore_administrator")).isEqualTo(1);
		assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable); assertThat(count("iam_administrator")).isZero();
		assertThat(count("iam_password")).isZero(); assertThat(count("iam_user_totp")).isZero();
		assertThat(this.keys.findPublicKey()).isEmpty(); assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
		var nextEnrollment = TotpTestSupport.distinctEnrollment(() -> {
			evictPoolConnections();
			return this.recovery.prepare(this.database, next.id(), this.userId, NEW_PASSWORD, RECOVERY);
		});
		evictPoolConnections(); assertThat(this.recovery.complete(this.database, next.id(), this.userId, nextEnrollment.factorId(), NEW_PASSWORD, referenceTotp(nextEnrollment, step()), RECOVERY)).isPresent();
		var nextKey = this.keys.recover(this.freshKey.id(), RELEASE);
		evictPoolConnections(); assertThat(this.releases.release(this.database, next.id(), this.userId, nextKey.id(), NEW_PASSWORD, freshTotp(nextEnrollment), RELEASE)).isPresent();
		this.restores.requireAvailable(); assertThat(count("iam_restore_release")).isEqualTo(2);
	}

	@Test
	void restoredAdministratorCanUseNormalEmergencyRecoveryWithoutForgingOriginalBootstrapHistory() {
		assertThat(this.jdbc.sql("SELECT completed_at IS NULL FROM iam_admin_bootstrap").query(Boolean.class).single()).isTrue();
		assertThat(release(NEW_PASSWORD, freshTotp(this.enrollment))).isPresent();
		var audit = new SecurityAuditContext("deployment:operator-2", "deployment:admin-recovery:CHANGE-125", UUID.randomUUID());
		var recovery = this.context.getBean(IdentityAdministratorRecoveries.class);
		var next = recovery.begin(this.userId, NEW_PASSWORD, audit).orElseThrow();
		assertThat(recovery.complete(this.userId, next.recoveryId(), next.token(), NEW_PASSWORD, referenceTotp(next.enrollment(), step()), audit)).isPresent();
		assertThat(this.jdbc.sql("SELECT completed_at IS NULL FROM iam_admin_bootstrap").query(Boolean.class).single()).isTrue();
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
	}

	@Test
	void wrongDatabaseRestoreKeySubjectAttributionAndAmbientTransactionCannotAuthorizeRelease() {
		String code = freshTotp(this.enrollment);
		for (String fault : List.of("database", "restore", "key", "user", "attribution")) {
			evictPoolConnections();
			assertThatThrownBy(() -> this.releases.release(fault.equals("database") ? "another-database" : this.database,
					fault.equals("restore") ? UUID.randomUUID() : this.restoreId, fault.equals("user") ? UUID.randomUUID() : this.userId,
					fault.equals("key") ? this.signing.id() : this.freshKey.id(), NEW_PASSWORD, code, fault.equals("attribution") ? AUDIT : RELEASE)).isInstanceOf(RuntimeException.class);
		}
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> assertThatIllegalStateException()
				.isThrownBy(() -> this.releases.release(this.database, this.restoreId, this.userId, this.freshKey.id(), NEW_PASSWORD, code, RELEASE))
				.withMessageContaining("independent transaction"));
		assertThat(count("iam_restore_release")).isZero();
	}

	private Optional<IdentityRestoreRelease> release(String password, String code) { evictPoolConnections(); return this.releases.release(this.database, this.restoreId, this.userId, this.freshKey.id(), password, code, RELEASE); }
	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }
	private String freshTotp(IdentityTotpEnrollment enrollment) {
		long last = this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:user AND factor_id=:factor")
				.param("user", enrollment.userId()).param("factor", enrollment.factorId()).query(Long.class).single();
		return referenceTotp(enrollment, Math.max(step(), last + 1));
	}
	private long step() {
		return this.jdbc.sql("SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::BIGINT").query(Long.class).single();
	}
	private static String referenceTotp(IdentityTotpEnrollment enrollment, long step) {
		byte[] counter = java.nio.ByteBuffer.allocate(8).putLong(step).array();
		var hmac = new HMac(new SHA1Digest()); hmac.init(new KeyParameter(Base32.decode(enrollment.secret()))); hmac.update(counter, 0, counter.length);
		byte[] hash = new byte[20]; hmac.doFinal(hash, 0); int position = hash[19] & 15;
		return String.format(java.util.Locale.ROOT, "%06d", (java.nio.ByteBuffer.wrap(hash, position, 4).getInt() & 0x7fffffff) % 1_000_000);
	}
	private static Path keyFile() {
		try { byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); Path file = Files.createTempFile("iam-restore-release-totp-", ".key"); Files.write(file, bytes); file.toFile().deleteOnExit(); return file; }
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}
}
