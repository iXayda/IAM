package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.GeneratedRecoveryCodes;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.RecoveryCodeOperations;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

class MfaLoginRollbackIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private MfaLoginOperations logins;

	@Autowired
	private MfaChallengeOperations challenges;

	@Autowired
	private RecoveryCodeOperations recoveryCodes;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@MockitoBean
	private SessionOperations sessions;

	private User user;

	@AfterEach
	void deleteFixtures() {
		if (this.user == null) {
			return;
		}
		this.jdbcClient.sql("DELETE FROM user_recovery_codes WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
	}

	@Test
	void restoresCredentialConsumptionButKeepsTheChallengeConsumedWhenSessionCreationFails() {
		this.user = createUser();
		char[][] codes = replaceAndCopy();
		try {
			LoginAttemptSource source = LoginAttemptSource.trusted("rollback-" + UUID.randomUUID());
			MfaChallenge failedChallenge = issue(source);
			UserSession session = session();
			when(this.sessions.start(eq(TenantId.DEFAULT), eq(this.user.id()),
					eq(SessionAuthenticationMethod.PASSWORD), any(), any()))
				.thenThrow(new IllegalStateException("simulated session write failure"))
				.thenReturn(session);

			try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt(codes[0])) {
				assertThatThrownBy(() -> this.logins.complete(failedChallenge, source, attempt))
					.isInstanceOf(IllegalStateException.class)
					.hasMessage("simulated session write failure");
			}
			assertThat(this.challenges.consume(failedChallenge, source))
				.isEqualTo(MfaChallengeConsumeStatus.REJECTED);
			assertThat(availableRecoveryCodeCount()).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT);
			assertThat(auditEventCount(source)).isZero();

			MfaChallenge retryChallenge = issue(source);
			try (RecoveryCodeAttempt retry = new RecoveryCodeAttempt(codes[0])) {
				assertThat(this.logins.complete(retryChallenge, source, retry).session()).contains(session);
			}
			assertThat(availableRecoveryCodeCount()).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT - 1);
			assertThat(auditEventCount(source)).isOne();
		}
		finally {
			clear(codes);
		}
	}

	private User createUser() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("mfa-rollback-" + suffix))));
	}

	private char[][] replaceAndCopy() {
		try (GeneratedRecoveryCodes generated = this.recoveryCodes.replace(TenantId.DEFAULT, this.user.id())) {
			return generated.copy();
		}
	}

	private MfaChallenge issue(LoginAttemptSource source) {
		return this.challenges.issue(TenantId.DEFAULT, this.user.id(), source, Instant.now().minusSeconds(1),
				Set.of(MfaFactor.RECOVERY_CODE)).challenge().orElseThrow();
	}

	private UserSession session() {
		Instant now = Instant.now();
		return UserSession.start(SessionId.random(), TenantId.DEFAULT, this.user.id(),
				SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, now.minusSeconds(1)),
						new SessionAuthenticationFactor(SessionAuthenticationFactorType.RECOVERY_CODE, now)),
				0, 0, now, now.plusSeconds(3600));
	}

	private int auditEventCount(LoginAttemptSource source) {
		return this.jdbcClient.sql("SELECT count(*) FROM audit_events WHERE source = :source")
			.param("source", source.value())
			.query(Integer.class)
			.single();
	}

	private int availableRecoveryCodeCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_recovery_codes
				WHERE tenant_id = :tenantId AND user_id = :userId AND consumed_at IS NULL
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.query(Integer.class)
			.single();
	}

	private static void clear(char[][] values) {
		for (char[] value : values) {
			Arrays.fill(value, '\0');
		}
	}

}
