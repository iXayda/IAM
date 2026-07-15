package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@TestPropertySource(properties = "iam.ratelimit.login.principal-limit=1")
class LocalPasswordLoginRollbackIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private LocalPasswordLoginOperations logins;

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
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
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
	void rollsBackCredentialUpgradeAndPreservesTheAttemptWhenSessionCreationFails() {
		this.user = createUser();
		String rawPassword = "legacy-password";
		String legacyHash = "{bcrypt}" + new BCryptPasswordEncoder(4).encode(rawPassword);
		this.jdbcClient.sql("""
				INSERT INTO user_password_credentials (tenant_id, user_id, encoded_password)
				VALUES (:tenantId, :userId, :encodedPassword)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.param("encodedPassword", legacyHash)
			.update();
		when(this.sessions.start(eq(TenantId.DEFAULT), eq(this.user.id()),
				eq(SessionAuthenticationMethod.PASSWORD), any()))
			.thenThrow(new IllegalStateException("simulated session write failure"));

		LoginAttemptSource source = LoginAttemptSource.trusted("rollback-" + UUID.randomUUID());
		try (PasswordAttempt attempt = new PasswordAttempt(rawPassword.toCharArray())) {
			assertThatThrownBy(() -> this.logins.login(TenantId.DEFAULT, loginKey(), source, attempt))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("simulated session write failure");
		}

		StoredCredential stored = storedCredential();
		assertThat(stored.encodedPassword()).isEqualTo(legacyHash);
		assertThat(stored.version()).isZero();
		try (PasswordAttempt retry = new PasswordAttempt(rawPassword.toCharArray())) {
			LocalPasswordLoginResult result = this.logins.login(TenantId.DEFAULT, loginKey(), source, retry);
			assertThat(result.status()).isEqualTo(LocalPasswordLoginStatus.THROTTLED);
		}
	}

	private User createUser() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("auth-rollback-" + suffix))));
	}

	private LoginKey loginKey() {
		return this.user.identifiers().getFirst().loginKey();
	}

	private StoredCredential storedCredential() {
		return this.jdbcClient.sql("""
				SELECT encoded_password, version
				FROM user_password_credentials
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", this.user.id().value())
			.query((resultSet, rowNumber) ->
					new StoredCredential(resultSet.getString("encoded_password"), resultSet.getLong("version")))
			.single();
	}

	private record StoredCredential(String encodedPassword, long version) {
	}

}
