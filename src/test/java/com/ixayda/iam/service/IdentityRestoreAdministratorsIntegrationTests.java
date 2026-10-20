package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.IdentityRestoreTestSupport;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.repository.IdentityRestoreAdministratorRepository;

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

class IdentityRestoreAdministratorsIntegrationTests extends IdentityRestoreTestSupport {

	private static final Path TOTP_KEY = keyFile();
	private static final String NEW_PASSWORD = "violet lighthouse cedar river 827";
	private static final SecurityAuditContext RECOVERY = new SecurityAuditContext("deployment:operator-1", "deployment:restore-admin:CHANGE-123", UUID.randomUUID());
	@Autowired private IdentityRestoreAdministrators recovery;
	@Autowired private IdentityRestores restores;
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityRestoreAdministratorRepository repository;
	private UUID restoreId;
	private String database;

	@DynamicPropertySource
	static void factorKey(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", TOTP_KEY::toString); }

	@BeforeEach
	void quarantineSnapshot() {
		this.database = this.restores.databaseName(); evictPoolConnections();
		this.restoreId = this.restores.quarantine(this.database, "a".repeat(64), new SecurityAuditContext("deployment:operator-1", "deployment:restore:CHANGE-122", UUID.randomUUID())).id();
	}

	@AfterEach
	void cleanRecoveryStateAndFaults() {
		for (String table : List.of("iam_restore_administrator", "iam_administrator", "iam_user_totp", "iam_mfa_recovery_code", "iam_security_audit", "iam_password")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS restore_admin_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS restore_admin_test_fault()").update();
		this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT IF EXISTS restore_admin_audit_fault").update();
		this.jdbc.sql("TRUNCATE iam_restore_release,iam_restore_administrator,iam_restore_state,iam_restore,iam_signing_key_state,iam_signing_key").update();
		this.jdbc.sql("INSERT INTO iam_restore_state(singleton) VALUES(1)").update(); this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
	}

	@Test
	void preparesAnExistingIdentityWithoutGrantingManagementAndCommitsOnlyAfterNewPasswordAndFactorVerification() {
		var identity = this.users.findById(this.userId).orElseThrow();
		var enrollment = prepare(NEW_PASSWORD); assertThat(this.administrators.findByUserId(this.userId)).isEmpty();
		assertThat(this.repository.find(this.restoreId).orElseThrow().completedAt()).isNull();
		assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
		assertThatIllegalStateException().isThrownBy(this.administrators::candidateId);
		var codes = complete(enrollment, NEW_PASSWORD, otp(enrollment)).orElseThrow();
		assertThat(codes.codes()).hasSize(10); assertThat(this.administrators.findByUserId(this.userId)).isPresent();
		var stored = this.repository.find(this.restoreId).orElseThrow(); assertThat(stored.completedAt()).isNotNull();
		assertThat(stored.userId()).isEqualTo(identity.id()); assertThat(stored.factorId()).isEqualTo(enrollment.factorId());
		assertThat(this.users.findById(this.userId).orElseThrow().createdAt()).isEqualTo(identity.createdAt());
		assertThat(count("iam_browser_session")).isZero(); assertThat(count("oauth2_authorization")).isZero();
		assertThat(this.jdbc.sql("SELECT restore_closed FROM iam_admin_bootstrap").query(Boolean.class).single()).isTrue();
		assertThatIllegalStateException().isThrownBy(this.restores::requireAvailable);
		var events = this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a WHERE action IN ('restore_admin_prepared','restore_admin_completed') ORDER BY action").query(String.class).list();
		assertThat(events).hasSize(2).allSatisfy(row -> {
			assertThat(row).contains(this.restoreId.toString(), this.userId.toString(), "database_restore", "deployment:operator-1").doesNotContain(NEW_PASSWORD, enrollment.secret());
			for (String code : codes.codes()) { assertThat(row).doesNotContain(code); }
		});
		assertThatIllegalStateException().isThrownBy(() -> prepare(NEW_PASSWORD));
		assertThatIllegalStateException().isThrownBy(() -> complete(enrollment, NEW_PASSWORD, otp(enrollment)));
		assertThat(this.repository.find(this.restoreId)).contains(stored);
	}

	@Test
	void renewedPreparationReplacesPendingCredentialsForTheSameIdentityAndRejectsEveryPreviousEnrollment() {
		var first = prepare(NEW_PASSWORD); var previous = this.repository.find(this.restoreId).orElseThrow();
		var next = prepare("willow orchard valley harbor 539");
		assertThat(next.factorId()).isNotEqualTo(first.factorId()); assertThat(next.secret()).isNotEqualTo(first.secret());
		assertThat(this.repository.find(this.restoreId).orElseThrow().preparedAt()).isEqualTo(previous.preparedAt());
		assertThatIllegalStateException().isThrownBy(() -> complete(first, NEW_PASSWORD, otp(first)));
		assertThat(complete(next, NEW_PASSWORD, otp(next))).isEmpty();
		assertThat(complete(next, "willow orchard valley harbor 539", otp(next))).isPresent();
	}

	@Test
	void wrongPasswordAndMalformedOrExpiredCodesCannotGrantAdministratorOrConsumeFreshEnrollment() {
		var enrollment = prepare(NEW_PASSWORD);
		assertThat(complete(enrollment, PASSWORD, otp(enrollment))).isEmpty();
		assertThat(complete(enrollment, NEW_PASSWORD, "invalid")).isEmpty();
		assertThat(this.administrators.findByUserId(this.userId)).isEmpty();
		assertThat(this.repository.find(this.restoreId).orElseThrow().completedAt()).isNull();
		assertThat(complete(enrollment, NEW_PASSWORD, otp(enrollment))).isPresent();
	}

	@Test
	void repeatedInvalidFactorsThrottleCompletionWithoutGrantingMembership() {
		var enrollment = prepare(NEW_PASSWORD);
		for (int attempt = 0; attempt < 5; attempt++) { assertThat(complete(enrollment, NEW_PASSWORD, "invalid")).isEmpty(); }
		assertThat(complete(enrollment, NEW_PASSWORD, otp(enrollment))).isEmpty();
		assertThat(count("iam_administrator")).isZero();
		assertThat(this.repository.find(this.restoreId).orElseThrow().completedAt()).isNull();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='restore_admin_throttled'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void untrustedAttributionCannotPrepareOrCompleteARecovery() {
		for (var audit : List.of(new SecurityAuditContext("deployment:", RECOVERY.source(), UUID.randomUUID()),
				new SecurityAuditContext("deployment:operator:extra", RECOVERY.source(), UUID.randomUUID()),
				new SecurityAuditContext(RECOVERY.actor(), "deployment:restore-admin:", UUID.randomUUID()))) {
			assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.prepare(this.database, this.restoreId, this.userId, NEW_PASSWORD, audit));
			assertThatIllegalArgumentException().isThrownBy(() -> this.recovery.complete(this.database, this.restoreId, this.userId, UUID.randomUUID(), NEW_PASSWORD, "123456", audit));
		}
		assertThat(count("iam_restore_administrator")).isZero(); assertThat(count("iam_password")).isZero();
	}

	@Test
	void recoveryIdentityAndCompletedEvidenceCannotBeChangedOrDeleted() {
		var enrollment = prepare(NEW_PASSWORD);
		for (String sql : List.of("UPDATE iam_restore_administrator SET user_id=gen_random_uuid()", "UPDATE iam_restore_administrator SET prepared_at=clock_timestamp()", "DELETE FROM iam_restore_administrator")) {
			assertThatThrownBy(() -> this.jdbc.sql(sql).update()).isInstanceOf(RuntimeException.class);
		}
		assertThat(complete(enrollment, NEW_PASSWORD, otp(enrollment))).isPresent();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_restore_administrator SET completed_at=NULL").update()).isInstanceOf(RuntimeException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_restore_administrator SET factor_id=gen_random_uuid()").update()).isInstanceOf(RuntimeException.class);
	}

	@Test
	void expiredEnrollmentRequiresAnotherAuthorizedPreparation() {
		var enrollment = prepare(NEW_PASSWORD);
		this.jdbc.sql("UPDATE iam_user_totp SET issued_at=clock_timestamp()-interval '11 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE user_id=:id")
				.param("id", this.userId).update();
		assertThat(complete(enrollment, NEW_PASSWORD, otp(enrollment))).isEmpty(); assertThat(count("iam_administrator")).isZero();
	}

	@Test
	void weakPasswordCannotEnableTheCandidateOrLeaveAnyRecoveryMaterial() {
		assertThatThrownBy(() -> prepare("password")).isInstanceOf(IllegalArgumentException.class);
		assertThat(this.users.findById(this.userId).orElseThrow().status().name()).isEqualTo("DISABLED");
		assertThat(count("iam_password")).isZero(); assertThat(count("iam_user_totp")).isZero(); assertThat(count("iam_restore_administrator")).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "iam_restore_administrator", "iam_password", "iam_security_audit" })
	void failedPreparationLeavesTheQuarantinedSubjectDisabledAndDoesNotDiscloseAnEnrollment(String table) {
		suppress(table, "INSERT");
		assertThatThrownBy(() -> prepare(NEW_PASSWORD)).isInstanceOf(RuntimeException.class);
		assertThat(this.users.findById(this.userId).orElseThrow().status().name()).isEqualTo("DISABLED");
		assertThat(count("iam_password")).isZero(); assertThat(count("iam_user_totp")).isZero(); assertThat(count("iam_restore_administrator")).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "iam_restore_administrator", "iam_administrator", "iam_user_totp", "iam_mfa_recovery_code" })
	void suppressedCompletionWritesRollBackFactorActivationMembershipRecoveryCodesAndSuccessAudit(String table) {
		var enrollment = prepare(NEW_PASSWORD); var previous = this.repository.find(this.restoreId).orElseThrow();
		suppress(table, table.equals("iam_administrator") || table.equals("iam_mfa_recovery_code") ? "INSERT" : "UPDATE");
		assertThatThrownBy(() -> complete(enrollment, NEW_PASSWORD, otp(enrollment))).isInstanceOf(RuntimeException.class);
		assertThat(this.repository.find(this.restoreId)).contains(previous); assertThat(count("iam_administrator")).isZero(); assertThat(count("iam_mfa_recovery_code")).isZero();
		assertThat(this.jdbc.sql("SELECT status FROM iam_user_totp WHERE user_id=:id").param("id", this.userId).query(String.class).single()).isEqualTo("pending");
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='restore_admin_completed'").query(Long.class).single()).isZero();
	}

	@Test
	void finalAuditFailureRollsBackTheWholeQualificationAndAllowsARealRetry() {
		var enrollment = prepare(NEW_PASSWORD);
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT restore_admin_audit_fault CHECK(action<>'restore_admin_completed') NOT VALID").update();
		assertThatThrownBy(() -> complete(enrollment, NEW_PASSWORD, otp(enrollment))).isInstanceOf(RuntimeException.class);
		assertThat(count("iam_administrator")).isZero(); assertThat(count("iam_mfa_recovery_code")).isZero();
		this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT restore_admin_audit_fault").update();
		assertThat(complete(enrollment, NEW_PASSWORD, otp(enrollment))).isPresent();
	}

	@Test
	void wrongRestoreDatabaseIdentityAndAmbientTransactionCannotChangeTheReservedSubject() {
		var enrollment = prepare(NEW_PASSWORD);
		evictPoolConnections(); assertThatIllegalStateException().isThrownBy(() -> this.recovery.prepare("another-database", this.restoreId, this.userId, NEW_PASSWORD, RECOVERY));
		evictPoolConnections(); assertThatIllegalStateException().isThrownBy(() -> this.recovery.prepare(this.database, UUID.randomUUID(), this.userId, NEW_PASSWORD, RECOVERY));
		evictPoolConnections(); assertThatIllegalStateException().isThrownBy(() -> this.recovery.prepare(this.database, this.restoreId, UUID.randomUUID(), NEW_PASSWORD, RECOVERY));
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> assertThatIllegalStateException().isThrownBy(() -> this.recovery.prepare(this.database, this.restoreId, this.userId, NEW_PASSWORD, RECOVERY)));
		assertThat(this.repository.find(this.restoreId).orElseThrow().factorId()).isEqualTo(enrollment.factorId());
	}

	private IdentityTotpEnrollment prepare(String password) { evictPoolConnections(); return this.recovery.prepare(this.database, this.restoreId, this.userId, password, RECOVERY); }
	private Optional<MfaRecoveryCodeSet> complete(IdentityTotpEnrollment enrollment, String password, String code) {
		evictPoolConnections(); return this.recovery.complete(this.database, this.restoreId, this.userId, enrollment.factorId(), password, code, RECOVERY);
	}
	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }
	private void suppress(String table, String operation) {
		this.jdbc.sql("CREATE FUNCTION restore_admin_test_fault() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END;'").update();
		this.jdbc.sql("CREATE TRIGGER restore_admin_test_fault BEFORE " + operation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION restore_admin_test_fault()").update();
	}
	private static Path keyFile() {
		try { var path = Files.createTempFile("iam-restore-admin-", ".key"); byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); Files.write(path, bytes); path.toFile().deleteOnExit(); return path; }
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}
	private static String otp(IdentityTotpEnrollment enrollment) {
		byte[] counter = java.nio.ByteBuffer.allocate(8).putLong(Math.floorDiv(Instant.now().getEpochSecond(), 30)).array();
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(enrollment.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		return String.format(java.util.Locale.ROOT, "%06d", (java.nio.ByteBuffer.wrap(hash).getInt(offset) & 0x7fff_ffff) % 1_000_000);
	}
}
