package com.ixayda.iam.user.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserConcurrentUpdateException;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserProfile;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcUserRepositoryStatusIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0ce3"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final LoginIdentifier USERNAME = LoginIdentifier.username("status-user");

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
				VALUES (:tenantId, 'user-status-tenant', 'User Status Tenant')
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
	void updatesStatusUsingTenantScopedOptimisticLocking() {
		User current = insert(user(TenantId.DEFAULT, CREATED_AT));
		User disabled = current.disable(CREATED_AT.plusSeconds(1));

		assertThat(update(current, disabled)).isEqualTo(disabled);
		assertThat(this.repository.findById(TenantId.DEFAULT, current.id())).contains(disabled);
		assertThatThrownBy(() -> update(current, disabled))
			.isInstanceOf(UserConcurrentUpdateException.class)
			.extracting("tenantId", "userId", "expectedVersion")
			.containsExactly(TenantId.DEFAULT, current.id(), 0L);
		assertThat(this.repository.findById(TenantId.DEFAULT, current.id())).contains(disabled);
	}

	@Test
	void rejectsChangingImmutableStateOrRegressingTime() {
		User current = user(TenantId.DEFAULT, CREATED_AT.plusSeconds(60));
		User changedId = new User(UserId.random(), current.tenantId(), current.identifiers(), UserStatus.DISABLED, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1), current.lastLoginAt());
		User changedTenant = new User(current.id(), SECOND_TENANT_ID, current.identifiers(), UserStatus.DISABLED, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1), current.lastLoginAt());
		User changedIdentifiers = new User(current.id(), current.tenantId(),
				List.of(LoginIdentifier.username("other-user")), UserStatus.DISABLED, 1, current.createdAt(),
				current.updatedAt().plusSeconds(1), current.lastLoginAt());
		User changedLastLogin = new User(current.id(), current.tenantId(), current.identifiers(), UserStatus.DISABLED, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1), CREATED_AT.plusSeconds(1));
		User changedCreationTime = new User(current.id(), current.tenantId(), current.identifiers(), UserStatus.DISABLED,
				1, current.createdAt().minusSeconds(1), current.updatedAt().plusSeconds(1), current.lastLoginAt());
		User skippedVersion = new User(current.id(), current.tenantId(), current.identifiers(), UserStatus.DISABLED, 2,
				current.createdAt(), current.updatedAt().plusSeconds(1), current.lastLoginAt());
		User regressedTime = new User(current.id(), current.tenantId(), current.identifiers(), UserStatus.DISABLED, 1,
				current.createdAt(), CREATED_AT.plusSeconds(30), current.lastLoginAt());
		User changedProfile = new User(current.id(), current.tenantId(), current.identifiers(),
				new UserProfile("Status User", null, null, null), UserStatus.DISABLED, 1, 1,
				current.createdAt(), current.updatedAt().plusSeconds(1), current.lastLoginAt());
		User unchangedSecurityVersion = new User(current.id(), current.tenantId(), current.identifiers(), current.profile(),
				UserStatus.DISABLED, 1, 0, current.createdAt(), current.updatedAt().plusSeconds(1), current.lastLoginAt());

		assertThatThrownBy(() -> update(current, changedId)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedTenant)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedIdentifiers)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedLastLogin)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedCreationTime)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, skippedVersion)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, regressedTime)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedProfile)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, unchangedSecurityVersion)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, current)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void doesNotUpdateAUserThroughAnotherTenant() {
		User stored = insert(user(TenantId.DEFAULT, CREATED_AT));
		User forgedCurrent = new User(stored.id(), SECOND_TENANT_ID, stored.identifiers(), stored.status(),
				stored.version(), stored.createdAt(), stored.updatedAt(), stored.lastLoginAt());
		User forgedChange = forgedCurrent.disable(CREATED_AT.plusSeconds(1));

		assertThatThrownBy(() -> update(forgedCurrent, forgedChange))
			.isInstanceOf(UserConcurrentUpdateException.class);
		assertThat(this.repository.findById(TenantId.DEFAULT, stored.id())).contains(stored);
	}

	@Test
	void requiresAnExistingReadWriteTransaction() {
		User current = user(TenantId.DEFAULT, CREATED_AT);
		User changed = current.disable(CREATED_AT.plusSeconds(1));

		assertThatThrownBy(() -> this.repository.updateStatus(current, changed))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.updateStatus(current, changed)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("User write requires an existing read-write transaction");
	}

	private User user(TenantId tenantId, Instant updatedAt) {
		return new User(UserId.random(), tenantId, List.of(USERNAME), UserStatus.ACTIVE, 0, CREATED_AT, updatedAt,
				CREATED_AT);
	}

	private User insert(User user) {
		this.usersToDelete.add(new UserReference(user.tenantId(), user.id()));
		return transactionTemplate().execute(status -> this.repository.insert(user));
	}

	private User update(User current, User changed) {
		return transactionTemplate().execute(status -> this.repository.updateStatus(current, changed));
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
