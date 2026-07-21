package com.ixayda.iam.credential.internal;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.credential.TotpCredentialStatus;
import com.ixayda.iam.credential.TotpEnrollment;
import com.ixayda.iam.credential.TotpOperations;
import com.ixayda.iam.session.SessionAbsoluteTtl;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpOperationsIntegrationTests extends ApplicationIntegrationTest {

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f601");

	@Autowired
	private TotpOperations operations;

	@Autowired
	private TotpCodeGenerator codeGenerator;

	@Autowired
	private TotpTimeSource timeSource;

	@Autowired
	private JdbcTotpCredentialRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private SessionOperations sessions;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createUser() {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("""
				INSERT INTO user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value)
				VALUES (:tenantId, :userId, 'username', 'totp-operations', 'totp-operations')
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE user_id = :userId")
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_totp_credentials WHERE user_id = :userId")
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@Test
	void enrollsActivatesConsumesAndRevokesTotpCredentials() {
		int activatedBefore = auditEventCount("credential.totp.activated");
		int revokedBefore = auditEventCount("credential.totp.revoked");
		assertThat(this.operations.hasActiveCredential(TenantId.DEFAULT, USER_ID)).isFalse();
		try (TotpEnrollment enrollment = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			byte[] secret = enrollment.copySecret();
			try {
				long timeStep = currentTimeStep();
				try (TotpCodeAttempt activation = attempt(secret, timeStep)) {
					assertThat(this.operations.activate(TenantId.DEFAULT, USER_ID, enrollment.credentialId(), activation))
						.isTrue();
				}
				assertThat(this.operations.hasActiveCredential(TenantId.DEFAULT, USER_ID)).isTrue();

				try (TotpCodeAttempt replay = attempt(secret, timeStep)) {
					assertThat(verify(replay)).isFalse();
				}
				long acceptedTimeStep = this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID)
					.map(stored -> stored.credential().lastAcceptedTimeStep())
					.orElseThrow();
				try (TotpCodeAttempt next = attempt(secret, acceptedTimeStep + 1)) {
					assertThat(verify(next)).isTrue();
				}
				try (TotpCodeAttempt replay = attempt(secret, acceptedTimeStep + 1)) {
					assertThat(verify(replay)).isFalse();
				}

				assertThat(this.operations.revoke(TenantId.DEFAULT, USER_ID, enrollment.credentialId())).isTrue();
				assertThat(this.operations.revoke(TenantId.DEFAULT, USER_ID, enrollment.credentialId())).isFalse();
				assertThat(this.operations.hasActiveCredential(TenantId.DEFAULT, USER_ID)).isFalse();
				StoredTotpCredential revoked = this.repository
					.findById(TenantId.DEFAULT, USER_ID, enrollment.credentialId())
					.orElseThrow();
				assertThat(revoked.credential().status()).isEqualTo(TotpCredentialStatus.REVOKED);
				assertThat(revoked.protectedSecret()).isNull();
			}
			finally {
				Arrays.fill(secret, (byte) 0);
			}
		}
		assertThat(auditEventCount("credential.totp.activated")).isEqualTo(activatedBefore + 1);
		assertThat(auditEventCount("credential.totp.revoked")).isEqualTo(revokedBefore + 1);
	}

	@Test
	void replacesPendingAndActiveCredentialsWithoutRetainingOldSecrets() {
		TotpCredentialId firstId;
		try (TotpEnrollment first = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			firstId = first.credentialId();
		}
		try (TotpEnrollment replacement = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			assertRevokedWithoutSecret(firstId);
			activate(replacement);
		}

		TotpCredentialId activeId = this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID)
			.map(stored -> stored.credential().id())
			.orElseThrow();
		try (TotpEnrollment replacement = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			activate(replacement);
			assertRevokedWithoutSecret(activeId);
			assertThat(this.repository.findActiveByUser(TenantId.DEFAULT, USER_ID).orElseThrow().credential().id())
				.isEqualTo(replacement.credentialId());
		}
	}

	@Test
	void leavesInvalidActivationPending() {
		try (TotpEnrollment enrollment = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			byte[] secret = enrollment.copySecret();
			try (TotpCodeAttempt invalid = invalidAttempt(secret)) {
				assertThat(this.operations.activate(TenantId.DEFAULT, USER_ID, enrollment.credentialId(), invalid))
					.isFalse();
				assertThat(this.repository.findPendingByUser(TenantId.DEFAULT, USER_ID).orElseThrow().credential().id())
					.isEqualTo(enrollment.credentialId());
			}
			finally {
				Arrays.fill(secret, (byte) 0);
			}
		}
	}

	@Test
	void invalidatesExistingSessionsOnlyWhenActiveTotpConfigurationChanges() {
		UserSession beforeActivation = startSession();
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, beforeActivation.id())).contains(beforeActivation);

		try (TotpEnrollment enrollment = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			assertThat(this.sessions.findUsable(TenantId.DEFAULT, beforeActivation.id())).contains(beforeActivation);
			activate(enrollment);
		}
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, beforeActivation.id())).isEmpty();

		UserSession beforePendingRevoke = startSession();
		try (TotpEnrollment pending = this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)) {
			assertThat(this.sessions.findUsable(TenantId.DEFAULT, beforePendingRevoke.id()))
				.contains(beforePendingRevoke);
			assertThat(this.operations.revoke(TenantId.DEFAULT, USER_ID, pending.credentialId())).isTrue();
		}
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, beforePendingRevoke.id())).contains(beforePendingRevoke);

		assertThat(this.operations.revokeActive(TenantId.DEFAULT, USER_ID)).isTrue();
		assertThat(this.operations.revokeActive(TenantId.DEFAULT, USER_ID)).isFalse();
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, beforePendingRevoke.id())).isEmpty();
	}

	@Test
	void enforcesEnrollmentAndVerificationTransactionBoundaries() {
		assertThatThrownBy(() -> transactionTemplate()
			.execute(status -> this.operations.beginEnrollment(TenantId.DEFAULT, USER_ID)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("TOTP enrollment must not run inside a database transaction");

		try (TotpCodeAttempt code = new TotpCodeAttempt("000000".toCharArray())) {
			assertThatThrownBy(() -> this.operations.verify(TenantId.DEFAULT, USER_ID, code))
				.isInstanceOf(IllegalTransactionStateException.class);
			TransactionTemplate readOnly = transactionTemplate();
			readOnly.setReadOnly(true);
			assertThatThrownBy(() -> readOnly.execute(status -> this.operations.verify(TenantId.DEFAULT, USER_ID, code)))
				.isInstanceOf(IllegalTransactionStateException.class);
		}
	}

	private void activate(TotpEnrollment enrollment) {
		byte[] secret = enrollment.copySecret();
		try (TotpCodeAttempt code = attempt(secret, currentTimeStep())) {
			assertThat(this.operations.activate(TenantId.DEFAULT, USER_ID, enrollment.credentialId(), code)).isTrue();
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
	}

	private boolean verify(TotpCodeAttempt code) {
		return transactionTemplate().execute(status -> this.operations.verify(TenantId.DEFAULT, USER_ID, code));
	}

	private UserSession startSession() {
		return transactionTemplate().execute(status -> this.sessions.start(TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD, new SessionAbsoluteTtl(Duration.ofHours(1))));
	}

	private TotpCodeAttempt attempt(byte[] secret, long timeStep) {
		return new TotpCodeAttempt(this.codeGenerator.generate(secret, timeStep).toCharArray());
	}

	private TotpCodeAttempt invalidAttempt(byte[] secret) {
		long current = currentTimeStep();
		Set<String> validCodes = new HashSet<>(List.of(
				this.codeGenerator.generate(secret, current - 1), this.codeGenerator.generate(secret, current),
				this.codeGenerator.generate(secret, current + 1)));
		for (int value = 0; value < 1_000_000; value++) {
			String candidate = String.format(Locale.ROOT, "%06d", value);
			if (!validCodes.contains(candidate)) {
				return new TotpCodeAttempt(candidate.toCharArray());
			}
		}
		throw new IllegalStateException("Unable to construct an invalid TOTP test code");
	}

	private long currentTimeStep() {
		return this.codeGenerator.timeStepAt(this.timeSource.now());
	}

	private int auditEventCount(String type) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM audit_events
				WHERE tenant_id = :tenantId AND user_id = :userId AND event_type = :type
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.param("type", type)
			.query(Integer.class)
			.single();
	}

	private void assertRevokedWithoutSecret(TotpCredentialId credentialId) {
		StoredTotpCredential revoked = this.repository.findById(TenantId.DEFAULT, USER_ID, credentialId).orElseThrow();
		assertThat(revoked.credential().status()).isEqualTo(TotpCredentialStatus.REVOKED);
		assertThat(revoked.protectedSecret()).isNull();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

}
