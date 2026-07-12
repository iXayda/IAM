package com.ixayda.iam.user.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserAlreadyExistsException;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcUserRepositoryInsertIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0ce2"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final List<UserReference> usersToDelete = new ArrayList<>();

	@Autowired
	private JdbcUserRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createSecondTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'user-insert-tenant', 'User Insert Tenant')
				""").param("tenantId", SECOND_TENANT_ID.value()).update();
	}

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("""
					DELETE FROM user_login_identifiers
					WHERE tenant_id = :tenantId AND user_id = :userId
					""")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
		});
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void insertsAUserAndAllLoginIdentifiersAtomically() {
		User user = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.phone("+1 (555) 123-4567"), LoginIdentifier.email("alice@example.com"),
						LoginIdentifier.username("alice")));

		assertThat(insert(user)).isEqualTo(user);
		assertThat(this.repository.findById(TenantId.DEFAULT, user.id())).contains(user);
	}

	@Test
	void requiresAnExistingReadWriteTransaction() {
		User withoutTransaction = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("without-transaction")));

		assertThatThrownBy(() -> this.repository.insert(withoutTransaction))
			.isInstanceOf(IllegalTransactionStateException.class);
		assertThat(userRows(withoutTransaction)).isZero();

		User inReadOnlyTransaction = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("read-only-transaction")));
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);

		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.insert(inReadOnlyTransaction)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("User write requires an existing read-write transaction");
		assertThat(userRows(inReadOnlyTransaction)).isZero();
	}

	@Test
	void rollsBackTheUserAndEarlierIdentifiersOnALoginConflict() {
		User reserved = user(TenantId.DEFAULT, UserStatus.DELETED,
				List.of(LoginIdentifier.username("15551234567")));
		insert(reserved);
		User candidate = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("candidate"), LoginIdentifier.email("candidate@example.com"),
						LoginIdentifier.phone("+1 (555) 123-4567")));
		String rawPhone = candidate.identifiers().get(2).value();
		String canonicalPhone = candidate.identifiers().get(2).canonicalValue();

		UserAlreadyExistsException conflict = catchThrowableOfType(UserAlreadyExistsException.class,
				() -> insert(candidate));

		assertThat(conflict.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(conflict).hasNoCause();
		assertThat(conflict.getMessage()).doesNotContain(rawPhone, canonicalPhone);
		assertThat(userRows(candidate)).isZero();
		assertThat(identifierRows(candidate)).isZero();
		assertThat(this.repository.findById(TenantId.DEFAULT, reserved.id())).contains(reserved);
	}

	@Test
	void allowsTheSameLoginKeyInDifferentTenants() {
		User first = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.email("shared@example.com")));
		User second = user(SECOND_TENANT_ID, UserStatus.ACTIVE,
				List.of(LoginIdentifier.email("SHARED@example.com")));

		insert(first);
		insert(second);

		assertThat(this.repository.findById(TenantId.DEFAULT, first.id())).contains(first);
		assertThat(this.repository.findById(SECOND_TENANT_ID, second.id())).contains(second);
	}

	private User insert(User user) {
		this.usersToDelete.add(new UserReference(user.tenantId(), user.id()));
		return transactionTemplate().execute(status -> this.repository.insert(user));
	}

	private User user(TenantId tenantId, UserStatus status, List<LoginIdentifier> identifiers) {
		return new User(UserId.random(), tenantId, identifiers, status, 0, CREATED_AT, CREATED_AT, null);
	}

	private int userRows(User user) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM users
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", user.tenantId().value())
			.param("userId", user.id().value())
			.query(Integer.class)
			.single();
	}

	private int identifierRows(User user) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM user_login_identifiers
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", user.tenantId().value())
			.param("userId", user.id().value())
			.query(Integer.class)
			.single();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
