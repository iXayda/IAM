package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class UserOperationsProfileIntegrationTests extends ApplicationIntegrationTest {

	private static final UserProfile FIRST_PROFILE =
			new UserProfile("Alice Example", "Alice Q. Example", "Alice", "Example");

	private static final UserProfile SECOND_PROFILE =
			new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen");

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.forEach(tenantId -> {
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
		});
	}

	@Test
	void updatesProfilesWithTenantScopedOptimisticConcurrency() {
		Tenant tenant = createTenant("update");
		User created = createUser(tenant.id(), "profile-update");

		User first = this.users.updateProfile(tenant.id(), created.id(), created.version(), FIRST_PROFILE);

		assertThat(first.profile()).isEqualTo(FIRST_PROFILE);
		assertThat(first.version()).isOne();
		assertThat(first.securityVersion()).isEqualTo(created.securityVersion());
		assertThat(first.updatedAt()).isAfterOrEqualTo(created.updatedAt());
		assertThat(this.users.findById(tenant.id(), created.id())).contains(first);
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("profile-update"))).contains(first);
		assertThatThrownBy(() -> this.users.updateProfile(tenant.id(), created.id(), created.version(), SECOND_PROFILE))
			.isInstanceOf(UserConcurrentUpdateException.class)
			.extracting("tenantId", "userId", "expectedVersion")
			.containsExactly(tenant.id(), created.id(), 0L);
		assertThat(this.users.updateProfile(tenant.id(), created.id(), first.version(), FIRST_PROFILE)).isEqualTo(first);

		User disabled = this.users.disable(tenant.id(), created.id());
		assertThat(disabled.securityVersion()).isEqualTo(created.securityVersion() + 1);
		User second = this.users.updateProfile(tenant.id(), created.id(), disabled.version(), SECOND_PROFILE);
		assertThat(second.profile()).isEqualTo(SECOND_PROFILE);
		assertThat(second.status()).isEqualTo(UserStatus.DISABLED);
		assertThat(second.version()).isEqualTo(3);
		assertThat(second.securityVersion()).isEqualTo(disabled.securityVersion());
	}

	@Test
	void rejectsDeletedUsersOtherTenantsAndDisabledTenants() {
		Tenant owner = createTenant("owner");
		Tenant other = createTenant("other");
		User created = createUser(owner.id(), "profile-guard");

		assertThatThrownBy(() -> this.users.updateProfile(other.id(), created.id(), 0, FIRST_PROFILE))
			.isInstanceOf(UserNotFoundException.class);
		User deleted = this.users.delete(owner.id(), created.id());
		assertThatThrownBy(() -> this.users.updateProfile(owner.id(), created.id(), deleted.version(), FIRST_PROFILE))
			.isInstanceOf(IllegalStateException.class);

		User otherUser = createUser(other.id(), "disabled-profile-tenant");
		this.tenants.disable(other.id());
		assertThatThrownBy(() -> this.users.updateProfile(other.id(), otherUser.id(), otherUser.version(), FIRST_PROFILE))
			.isInstanceOf(TenantDisabledException.class);
	}

	@Test
	void allowsOnlyOneUpdateForTheSameExpectedVersion() throws Exception {
		Tenant tenant = createTenant("concurrent");
		User created = createUser(tenant.id(), "concurrent-profile");
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<UpdateResult>> pending = new ArrayList<>();
		List<UpdateResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> update(tenant.id(), created, FIRST_PROFILE, ready, start)));
			pending.add(executor.submit(() -> update(tenant.id(), created, SECOND_PROFILE, ready, start)));
			boolean bothReady;
			try {
				bothReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(bothReady).isTrue();
			for (Future<UpdateResult> result : pending) {
				results.add(result.get(10, TimeUnit.SECONDS));
			}
		}

		assertThat(results.stream().filter(result -> result.user() != null)).hasSize(1);
		assertThat(results.stream().filter(result -> result.failure() != null))
			.singleElement()
			.satisfies(result -> assertThat(result.failure()).isInstanceOf(UserConcurrentUpdateException.class));
		User stored = this.users.findById(tenant.id(), created.id()).orElseThrow();
		assertThat(stored.version()).isOne();
		assertThat(stored.securityVersion()).isEqualTo(created.securityVersion());
		assertThat(stored.profile()).isIn(FIRST_PROFILE, SECOND_PROFILE);
	}

	private UpdateResult update(TenantId tenantId, User user, UserProfile profile, CountDownLatch ready,
			CountDownLatch start) {
		try {
			ready.countDown();
			start.await();
			return new UpdateResult(this.users.updateProfile(tenantId, user.id(), user.version(), profile), null);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			return new UpdateResult(null, new IllegalStateException("Interrupted while updating a user profile", ex));
		}
		catch (RuntimeException ex) {
			return new UpdateResult(null, ex);
		}
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants
			.create(new CreateTenantRequest("profile-" + purpose + "-" + suffix, "User Profile Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User createUser(TenantId tenantId, String username) {
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(username))));
	}

	private record UpdateResult(User user, RuntimeException failure) {
	}

}
