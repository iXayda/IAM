package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;

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
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class MfaLoginOperationsIntegrationTests extends ApplicationIntegrationTest {

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
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
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
	void consumesARecoveryCodeAndStartsOneSessionAtomically() {
		this.user = createUser("success");
		char[][] codes = replaceAndCopy();
		try {
			LoginAttemptSource source = trustedSource("success");
			MfaChallenge challenge = issue(source);
			try (RecoveryCodeAttempt code = new RecoveryCodeAttempt(codes[0])) {
				MfaLoginResult result = this.logins.complete(challenge, source, code);

				assertThat(result.authenticated()).isTrue();
				assertThat(result.session()).hasValueSatisfying(session -> {
					assertThat(session.tenantId()).isEqualTo(TenantId.DEFAULT);
					assertThat(session.userId()).isEqualTo(this.user.id());
				});
			}
			assertThat(sessionCount()).isOne();
			assertThat(availableRecoveryCodeCount()).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT - 1);

			try (RecoveryCodeAttempt replay = new RecoveryCodeAttempt(codes[1])) {
				assertThat(this.logins.complete(challenge, source, replay)).isSameAs(MfaLoginResult.rejected());
			}
			assertThat(sessionCount()).isOne();
			assertThat(availableRecoveryCodeCount()).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT - 1);
		}
		finally {
			clear(codes);
		}
	}

	@Test
	void consumesTheChallengeButNotARecoveryCodeWhenVerificationFails() {
		this.user = createUser("rejected");
		char[][] codes = replaceAndCopy();
		try {
			LoginAttemptSource source = trustedSource("rejected");
			MfaChallenge challenge = issue(source);
			try (RecoveryCodeAttempt invalid =
					new RecoveryCodeAttempt("00000-00000-00000-00000".toCharArray())) {
				assertThat(this.logins.complete(challenge, source, invalid)).isSameAs(MfaLoginResult.rejected());
			}
			try (RecoveryCodeAttempt valid = new RecoveryCodeAttempt(codes[0])) {
				assertThat(this.logins.complete(challenge, source, valid)).isSameAs(MfaLoginResult.rejected());
			}

			assertThat(sessionCount()).isZero();
			assertThat(availableRecoveryCodeCount()).isEqualTo(GeneratedRecoveryCodes.CODE_COUNT);
		}
		finally {
			clear(codes);
		}
	}

	private User createUser(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("mfa-login-" + purpose + "-" + suffix))));
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

	private LoginAttemptSource trustedSource(String purpose) {
		return LoginAttemptSource.trusted(purpose + "-" + UUID.randomUUID());
	}

	private int sessionCount() {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM user_sessions
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
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
