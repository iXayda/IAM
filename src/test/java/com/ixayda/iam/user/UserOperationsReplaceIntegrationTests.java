package com.ixayda.iam.user;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserOperationsReplaceIntegrationTests extends ApplicationIntegrationTest {

	private static final UserProfile PROFILE =
			new UserProfile("Replacement User", "Replacement Q. User", "Replacement", "User");

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.forEach((tenantId) -> {
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
	void replacesIdentifiersProfileAndActiveStateAtomically() {
		Tenant tenant = createTenant("state");
		User created = this.users.create(tenant.id(), new CreateUserRequest(List.of(
				LoginIdentifier.username("replace-old"), LoginIdentifier.email("replace-old@example.com"))));
		List<LoginIdentifier> replacementIdentifiers = List.of(LoginIdentifier.username("replace-new"),
				LoginIdentifier.phone("+1-555-123-4567"));

		User replaced = this.users.replace(tenant.id(), created.id(), created.version(),
				new ReplaceUserRequest(replacementIdentifiers, PROFILE, false));

		assertThat(replaced.identifiers()).isEqualTo(replacementIdentifiers);
		assertThat(replaced.profile()).isEqualTo(PROFILE);
		assertThat(replaced.status()).isEqualTo(UserStatus.DISABLED);
		assertThat(replaced.version()).isOne();
		assertThat(replaced.securityVersion()).isOne();
		assertThat(this.users.findById(tenant.id(), created.id())).contains(replaced);
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("replace-old"))).isEmpty();
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("replace-old@example.com"))).isEmpty();
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("replace-new"))).contains(replaced);
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("+15551234567"))).contains(replaced);

		User active = this.users.activate(tenant.id(), created.id());
		User locked = this.users.lock(tenant.id(), active.id());
		User preserved = this.users.replace(tenant.id(), created.id(), locked.version(),
				new ReplaceUserRequest(locked.identifiers(), locked.profile(), false));
		assertThat(preserved).isEqualTo(locked);
		assertThat(preserved.status()).isEqualTo(UserStatus.LOCKED);
	}

	@Test
	void advancesSecurityRevisionWhenOnlyLoginIdentifiersChange() {
		Tenant tenant = createTenant("identifier-security");
		User current = this.users.create(tenant.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("replace-security-old"))));

		User replaced = this.users.replace(tenant.id(), current.id(), current.version(), new ReplaceUserRequest(
				List.of(LoginIdentifier.username("replace-security-new")), current.profile(), null));

		assertThat(replaced.status()).isEqualTo(current.status());
		assertThat(replaced.version()).isEqualTo(current.version() + 1);
		assertThat(replaced.securityVersion()).isEqualTo(current.securityVersion() + 1);
		assertThat(this.users.findById(tenant.id(), current.id())).contains(replaced);
	}

	@Test
	void rollsBackEveryReplacementValueOnUniquenessConflict() {
		Tenant tenant = createTenant("rollback");
		this.users.create(tenant.id(), new CreateUserRequest(List.of(LoginIdentifier.email("reserved@example.com"))));
		User current = this.users.create(tenant.id(), new CreateUserRequest(List.of(
				LoginIdentifier.username("rollback-old"), LoginIdentifier.phone("+15551234568"))));
		ReplaceUserRequest request = new ReplaceUserRequest(List.of(LoginIdentifier.username("rollback-new"),
				LoginIdentifier.email("RESERVED@example.com")), PROFILE, false);

		assertThatThrownBy(() -> this.users.replace(tenant.id(), current.id(), current.version(), request))
			.isInstanceOf(UserAlreadyExistsException.class);

		assertThat(this.users.findById(tenant.id(), current.id())).contains(current);
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("rollback-old"))).contains(current);
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("+15551234568"))).contains(current);
		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("rollback-new"))).isEmpty();
	}

	@Test
	void rejectsStaleDeletedCrossTenantAndDisabledTenantReplacements() {
		Tenant owner = createTenant("owner");
		Tenant other = createTenant("other");
		User current = this.users.create(owner.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("replace-guard"))));
		ReplaceUserRequest request = new ReplaceUserRequest(current.identifiers(), PROFILE, null);

		assertThatThrownBy(() -> this.users.replace(owner.id(), current.id(), current.version() + 1, request))
			.isInstanceOf(UserConcurrentUpdateException.class);
		assertThatThrownBy(() -> this.users.replace(other.id(), current.id(), current.version(), request))
			.isInstanceOf(UserNotFoundException.class);
		User deleted = this.users.delete(owner.id(), current.id());
		assertThatThrownBy(() -> this.users.replace(owner.id(), current.id(), deleted.version(), request))
			.isInstanceOf(UserNotFoundException.class);

		User otherUser = this.users.create(other.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("replace-disabled"))));
		this.tenants.disable(other.id());
		assertThatThrownBy(() -> this.users.replace(other.id(), otherUser.id(), otherUser.version(), request))
			.isInstanceOf(TenantDisabledException.class);
	}

	@Test
	void allowsOnlyOneReplacementForTheSameExpectedVersion() throws Exception {
		Tenant tenant = createTenant("concurrent");
		User current = this.users.create(tenant.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("replace-concurrent"))));
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<ReplaceResult>> pending = new ArrayList<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> replace(tenant.id(), current, "replace-first", ready, start)));
			pending.add(executor.submit(() -> replace(tenant.id(), current, "replace-second", ready, start)));
			boolean bothReady;
			try {
				bothReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(bothReady).isTrue();
			List<ReplaceResult> results = List.of(pending.get(0).get(10, TimeUnit.SECONDS),
					pending.get(1).get(10, TimeUnit.SECONDS));
			assertThat(results.stream().filter((result) -> result.user() != null)).hasSize(1);
			assertThat(results.stream().filter((result) -> result.failure() instanceof UserConcurrentUpdateException))
				.hasSize(1);
		}
	}

	@Test
	void allowsOnlyOneUserToClaimTheSameReplacementIdentifier() throws Exception {
		Tenant tenant = createTenant("identifier-race");
		User first = this.users.create(tenant.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("replace-race-first"))));
		User second = this.users.create(tenant.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("replace-race-second"))));
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<ReplaceResult>> pending = new ArrayList<>();
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			pending.add(executor.submit(() -> replace(tenant.id(), first, "replace-race-shared", ready, start)));
			pending.add(executor.submit(() -> replace(tenant.id(), second, "replace-race-shared", ready, start)));
			boolean bothReady;
			try {
				bothReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(bothReady).isTrue();
			List<ReplaceResult> results = List.of(pending.get(0).get(10, TimeUnit.SECONDS),
					pending.get(1).get(10, TimeUnit.SECONDS));
			assertThat(results.stream().filter((result) -> result.user() != null)).hasSize(1);
			assertThat(results.stream().filter((result) -> result.failure() instanceof UserAlreadyExistsException))
				.hasSize(1);
		}

		assertThat(this.users.findByLogin(tenant.id(), LoginKey.from("replace-race-shared"))).isPresent();
		assertThat(List.of("replace-race-first", "replace-race-second").stream()
			.filter((login) -> this.users.findByLogin(tenant.id(), LoginKey.from(login)).isPresent()))
			.hasSize(1);
	}

	private ReplaceResult replace(TenantId tenantId, User current, String username, CountDownLatch ready,
			CountDownLatch start) {
		try {
			ready.countDown();
			start.await();
			User replaced = this.users.replace(tenantId, current.id(), current.version(),
					new ReplaceUserRequest(List.of(LoginIdentifier.username(username)), UserProfile.empty(), null));
			return new ReplaceResult(replaced, null);
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			return new ReplaceResult(null, new IllegalStateException("Interrupted while replacing a user", exception));
		}
		catch (RuntimeException exception) {
			return new ReplaceResult(null, exception);
		}
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants
			.create(new CreateTenantRequest("replace-" + purpose + "-" + suffix, "User Replace Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private record ReplaceResult(User user, RuntimeException failure) {
	}

}
