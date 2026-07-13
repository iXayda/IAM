package com.ixayda.iam.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class PasswordOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<UserId> usersToDelete = new ArrayList<>();

	@Autowired
	private PasswordOperations passwords;

	@Autowired
	private UserOperations users;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(userId -> {
			this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("userId", userId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("userId", userId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("userId", userId.value())
				.update();
		});
	}

	@Test
	void setsReplacesAndVerifiesAUserPassword() {
		User user = createUser("round-trip");
		setPassword(user, "initial-password");

		StoredCredential initial = storedCredential(user);
		assertThat(initial.encodedPassword()).startsWith("{pbkdf2@SpringSecurity_v5_8}");
		assertThat(initial.version()).isZero();
		assertThat(verify(user, "wrong-password")).isFalse();
		assertThat(verify(user, "initial-password")).isTrue();
		assertThat(storedCredential(user).version()).isZero();

		setPassword(user, "replacement-password");

		StoredCredential replacement = storedCredential(user);
		assertThat(replacement.version()).isEqualTo(1);
		assertThat(replacement.encodedPassword()).isNotEqualTo(initial.encodedPassword());
		assertThat(verify(user, "initial-password")).isFalse();
		assertThat(verify(user, "replacement-password")).isTrue();
	}

	@Test
	void requiresAnExistingReadWriteTransactionForVerification() {
		User user = createUser("transaction");
		setPassword(user, "correct-password");

		try (PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray())) {
			assertThatThrownBy(() -> this.passwords.verifyPassword(TenantId.DEFAULT, user.id(), attempt))
				.isInstanceOf(IllegalTransactionStateException.class);
		}

		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		try (PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray())) {
			assertThatThrownBy(() -> readOnly
				.execute(status -> this.passwords.verifyPassword(TenantId.DEFAULT, user.id(), attempt)))
				.isInstanceOf(IllegalTransactionStateException.class)
				.hasMessage("Password verification requires an existing read-write transaction");
		}
	}

	@Test
	void upgradesAValidLegacyBcryptHash() {
		User user = createUser("legacy");
		String rawPassword = "legacy-password";
		String legacyHash = "{bcrypt}" + new BCryptPasswordEncoder(4).encode(rawPassword);
		this.jdbcClient.sql("""
				INSERT INTO user_password_credentials (tenant_id, user_id, encoded_password)
				VALUES (:tenantId, :userId, :encodedPassword)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", user.id().value())
			.param("encodedPassword", legacyHash)
			.update();

		assertThat(verify(user, rawPassword)).isTrue();

		StoredCredential upgraded = storedCredential(user);
		assertThat(upgraded.encodedPassword()).startsWith("{pbkdf2@SpringSecurity_v5_8}");
		assertThat(upgraded.version()).isEqualTo(1);
		assertThat(this.passwordEncoder.matches(rawPassword, upgraded.encodedPassword())).isTrue();
	}

	private User createUser(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(TenantId.DEFAULT,
				new CreateUserRequest(List.of(LoginIdentifier.username("password-" + purpose + "-" + suffix))));
		this.usersToDelete.add(user.id());
		return user;
	}

	private void setPassword(User user, String value) {
		try (NewPassword password = new NewPassword(value.toCharArray())) {
			this.passwords.setPassword(TenantId.DEFAULT, user.id(), password);
		}
	}

	private boolean verify(User user, String value) {
		try (PasswordAttempt attempt = new PasswordAttempt(value.toCharArray())) {
			return Boolean.TRUE.equals(transactionTemplate()
				.execute(status -> this.passwords.verifyPassword(TenantId.DEFAULT, user.id(), attempt)));
		}
	}

	private StoredCredential storedCredential(User user) {
		return this.jdbcClient.sql("""
				SELECT encoded_password, version
				FROM user_password_credentials
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", user.id().value())
			.query((resultSet, rowNumber) ->
					new StoredCredential(resultSet.getString("encoded_password"), resultSet.getLong("version")))
			.single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private record StoredCredential(String encodedPassword, long version) {
	}

}
