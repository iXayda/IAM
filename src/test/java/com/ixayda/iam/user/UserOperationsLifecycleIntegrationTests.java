package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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

class UserOperationsLifecycleIntegrationTests extends ApplicationIntegrationTest {

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
	void changesStatusIdempotently() {
		Tenant tenant = createTenant("lifecycle");
		User created = createUser(tenant.id(), "lifecycle-user");

		assertThat(this.users.requireActive(tenant.id(), created.id())).isEqualTo(created);

		User disabled = this.users.disable(tenant.id(), created.id());
		assertThat(disabled.status()).isEqualTo(UserStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(this.users.disable(tenant.id(), created.id())).isEqualTo(disabled);
		assertThatThrownBy(() -> this.users.requireActive(tenant.id(), created.id()))
			.isInstanceOf(UserNotActiveException.class);

		User active = this.users.activate(tenant.id(), created.id());
		assertThat(active.status()).isEqualTo(UserStatus.ACTIVE);
		assertThat(active.version()).isEqualTo(2);
		assertThat(this.users.requireActive(tenant.id(), created.id())).isEqualTo(active);

		User locked = this.users.lock(tenant.id(), created.id());
		assertThat(locked.status()).isEqualTo(UserStatus.LOCKED);
		assertThat(locked.version()).isEqualTo(3);
		assertThat(this.users.lock(tenant.id(), created.id())).isEqualTo(locked);

		User deleted = this.users.delete(tenant.id(), created.id());
		assertThat(deleted.status()).isEqualTo(UserStatus.DELETED);
		assertThat(deleted.version()).isEqualTo(4);
		assertThat(this.users.delete(tenant.id(), created.id())).isEqualTo(deleted);
		assertThatThrownBy(() -> this.users.activate(tenant.id(), created.id()))
			.isInstanceOf(InvalidUserStatusTransitionException.class);
	}

	@Test
	void doesNotExposeAUserThroughAnotherTenant() {
		Tenant owner = createTenant("owner");
		Tenant other = createTenant("other");
		User created = createUser(owner.id(), "isolated-user");

		assertThat(this.users.findById(other.id(), created.id())).isEmpty();
		assertThat(this.users.findByLogin(other.id(), LoginKey.from("isolated-user"))).isEmpty();
		assertThatThrownBy(() -> this.users.disable(other.id(), created.id()))
			.isInstanceOf(UserNotFoundException.class);
		assertThat(this.users.findById(owner.id(), created.id())).contains(created);
	}

	@Test
	void rejectsActiveAccessAndWritesForADisabledTenant() {
		Tenant tenant = createTenant("disabled");
		User created = createUser(tenant.id(), "disabled-tenant-user");
		this.tenants.disable(tenant.id());

		assertThat(this.users.findById(tenant.id(), created.id())).contains(created);
		assertThatThrownBy(() -> this.users.requireActive(tenant.id(), created.id()))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.users.disable(tenant.id(), created.id()))
			.isInstanceOf(TenantDisabledException.class);
		assertThat(this.users.findById(tenant.id(), created.id())).contains(created);
	}

	@Test
	void keepsDeletedLoginIdentifiersReserved() {
		Tenant tenant = createTenant("deleted");
		LoginIdentifier username = LoginIdentifier.username("reserved-user");
		User created = this.users.create(tenant.id(), new CreateUserRequest(List.of(username)));
		User deleted = this.users.delete(tenant.id(), created.id());

		assertThat(this.users.findByLogin(tenant.id(), username.loginKey())).contains(deleted);
		assertThatThrownBy(() -> this.users.create(tenant.id(), new CreateUserRequest(List.of(username))))
			.isInstanceOf(UserAlreadyExistsException.class);
		assertThat(userRows(tenant.id())).isOne();
		assertThat(identifierRows(tenant.id())).isOne();
	}

	@Test
	void toleratesAStoredTimestampAheadOfTheSystemClock() {
		Tenant tenant = createTenant("future-time");
		User created = createUser(tenant.id(), "future-time-user");
		Instant future = created.updatedAt().plusSeconds(3_600);
		this.jdbcClient.sql("""
				UPDATE users SET updated_at = :updatedAt
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("updatedAt", OffsetDateTime.ofInstant(future, ZoneOffset.UTC))
			.param("tenantId", tenant.id().value())
			.param("userId", created.id().value())
			.update();

		User disabled = this.users.disable(tenant.id(), created.id());

		assertThat(disabled.status()).isEqualTo(UserStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(disabled.updatedAt()).isEqualTo(future);
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant =
				this.tenants.create(new CreateTenantRequest("user-" + purpose + "-" + suffix, "User Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User createUser(TenantId tenantId, String username) {
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(username))));
	}

	private int userRows(TenantId tenantId) {
		return this.jdbcClient.sql("SELECT count(*) FROM users WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.query(Integer.class)
			.single();
	}

	private int identifierRows(TenantId tenantId) {
		return this.jdbcClient.sql("SELECT count(*) FROM user_login_identifiers WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.query(Integer.class)
			.single();
	}

}
