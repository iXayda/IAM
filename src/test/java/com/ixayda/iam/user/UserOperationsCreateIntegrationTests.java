package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class UserOperationsCreateIntegrationTests extends ApplicationIntegrationTest {

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private UserOperations users;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

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
	void createsAndFindsAUserWithAllLoginIdentifiers() {
		Tenant tenant = createTenant();
		List<LoginIdentifier> identifiers = List.of(LoginIdentifier.username("alice"),
				LoginIdentifier.email("Alice@example.com"), LoginIdentifier.phone("+1 (555) 123-4567"));

		User created = this.users.create(tenant.id(), new CreateUserRequest(identifiers));

		assertThat(created.tenantId()).isEqualTo(tenant.id());
		assertThat(created.identifiers()).containsExactlyElementsOf(identifiers);
		assertThat(created.status()).isEqualTo(UserStatus.ACTIVE);
		assertThat(created.version()).isZero();
		assertThat(created.createdAt()).isEqualTo(created.updatedAt());
		assertThat(created.lastLoginAt()).isNull();
		assertThat(this.users.findById(tenant.id(), created.id())).contains(created);
		for (LoginIdentifier identifier : identifiers) {
			assertThat(this.users.findByLogin(tenant.id(), identifier.loginKey())).contains(created);
		}
		assertThat(userRows(tenant.id())).isOne();
		assertThat(identifierRows(tenant.id())).isEqualTo(3);
	}

	@Test
	void rollsBackTheWholeCreateOnALateIdentifierConflict() {
		Tenant tenant = createTenant();
		LoginIdentifier reservedPhone = LoginIdentifier.phone("+1 (555) 123-4567");
		this.users.create(tenant.id(), new CreateUserRequest(List.of(reservedPhone)));
		LoginIdentifier candidateUsername = LoginIdentifier.username("candidate");
		LoginIdentifier candidateEmail = LoginIdentifier.email("candidate@example.com");
		CreateUserRequest candidate = new CreateUserRequest(
				List.of(candidateUsername, candidateEmail, reservedPhone));

		assertThatThrownBy(() -> this.users.create(tenant.id(), candidate))
			.isInstanceOf(UserAlreadyExistsException.class);

		assertThat(userRows(tenant.id())).isOne();
		assertThat(identifierRows(tenant.id())).isOne();
		assertThat(identifierRows(tenant.id(), candidateUsername.loginKey())).isZero();
		assertThat(identifierRows(tenant.id(), candidateEmail.loginKey())).isZero();
	}

	@Test
	void rejectsCreateForADisabledTenant() {
		Tenant tenant = createTenant();
		this.tenants.disable(tenant.id());

		assertThatThrownBy(() -> this.users.create(tenant.id(),
				new CreateUserRequest(List.of(LoginIdentifier.username("blocked-user")))))
			.isInstanceOf(TenantDisabledException.class);
		assertThat(userRows(tenant.id())).isZero();
		assertThat(identifierRows(tenant.id())).isZero();
	}

	@Test
	void participatesInAnOuterRollback() {
		Tenant tenant = createTenant();
		TransactionTemplate transaction = new TransactionTemplate(this.transactionManager);

		transaction.executeWithoutResult(status -> {
			this.users.create(tenant.id(),
					new CreateUserRequest(List.of(LoginIdentifier.username("rolled-back-user"))));
			status.setRollbackOnly();
		});

		assertThat(userRows(tenant.id())).isZero();
		assertThat(identifierRows(tenant.id())).isZero();
	}

	private Tenant createTenant() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("user-create-" + suffix, "User Create Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
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

	private int identifierRows(TenantId tenantId, LoginKey loginKey) {
		return this.jdbcClient.sql("""
				SELECT count(*) FROM user_login_identifiers
				WHERE tenant_id = :tenantId AND canonical_value = :canonicalValue
				""")
			.param("tenantId", tenantId.value())
			.param("canonicalValue", loginKey.canonicalValue())
			.query(Integer.class)
			.single();
	}

}
