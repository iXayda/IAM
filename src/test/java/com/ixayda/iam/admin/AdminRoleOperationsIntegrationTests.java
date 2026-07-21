package com.ixayda.iam.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
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
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class AdminRoleOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private AdminRoleOperations roles;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.reversed().forEach(tenantId -> {
			this.jdbcClient.sql("DELETE FROM admin_role_bindings WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
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
	void bootstrapsOneSuperAdminAndResolvesEffectivePermissions() {
		Tenant tenant = createTenant("bootstrap");
		User admin = createUser(tenant.id(), "bootstrap-admin");

		AdminRoleBinding binding = this.roles.bootstrapSuperAdmin(tenant.id(), admin.id());

		assertThat(binding.roleCode()).isEqualTo(AdminRoleCode.SUPER_ADMIN);
		assertThat(binding.createdByUserId()).isNull();
		assertThat(this.roles.findRoles()).hasSize(5).allMatch(AdminRole::protectedRole);
		assertThat(this.roles.findEffectivePermissions(tenant.id(), admin.id())).hasSize(23);
		assertThat(this.roles.hasPermission(tenant.id(), admin.id(), AdminPermissionCode.ASSIGN_ROLES)).isTrue();
		assertThatThrownBy(() -> this.roles.bootstrapSuperAdmin(tenant.id(), admin.id()))
			.isInstanceOf(AdminRoleBootstrapUnavailableException.class);
	}

	@Test
	void allowsOnlyOneOfTwoConcurrentTenantBootstraps() throws Exception {
		Tenant tenant = createTenant("concurrent-bootstrap");
		User first = createUser(tenant.id(), "first-admin");
		User second = createUser(tenant.id(), "second-admin");
		CountDownLatch ready = new CountDownLatch(2);
		CountDownLatch start = new CountDownLatch(1);
		List<Object> results;

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Object> firstResult = executor.submit(() -> attemptBootstrap(tenant.id(), first.id(), ready, start));
			Future<Object> secondResult =
					executor.submit(() -> attemptBootstrap(tenant.id(), second.id(), ready, start));
			assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
			start.countDown();
			results = List.of(firstResult.get(10, TimeUnit.SECONDS), secondResult.get(10, TimeUnit.SECONDS));
		}

		assertThat(results).filteredOn(AdminRoleBinding.class::isInstance).hasSize(1);
		assertThat(results).filteredOn(AdminRoleBootstrapUnavailableException.class::isInstance).hasSize(1);
		assertThat(this.roles.findBindings(tenant.id(), first.id()).size()
				+ this.roles.findBindings(tenant.id(), second.id()).size()).isOne();
	}

	@Test
	void appliesGrantHierarchyAndBoundedJitAccess() {
		Tenant tenant = createTenant("hierarchy");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User manager = createUser(tenant.id(), "manager");
		User target = createUser(tenant.id(), "target");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), manager.id(), AdminRoleCode.ADMIN_MANAGER,
				"Delegated administration");

		AdminRoleBinding jit = this.roles.grantJustInTime(tenant.id(), manager.id(), target.id(),
				AdminRoleCode.from("user_manager"), Instant.now().plusSeconds(3_600), "On-call support");

		assertThat(jit.type()).isEqualTo(AdminRoleBindingType.JIT);
		assertThat(jit.reason()).isEqualTo("On-call support");
		assertThat(this.roles.findEffectivePermissions(tenant.id(), target.id()))
			.contains(AdminPermissionCode.from("user.read"), AdminPermissionCode.from("user.session.revoke"))
			.hasSize(7);
		assertThatThrownBy(() -> this.roles.grantPermanent(tenant.id(), manager.id(), target.id(),
				AdminRoleCode.SUPER_ADMIN, "Escalation")).isInstanceOf(AdminRoleGrantDeniedException.class);
		assertThatThrownBy(() -> this.roles.grantPermanent(tenant.id(), manager.id(), manager.id(),
				AdminRoleCode.from("support"), "Self grant")).isInstanceOf(AdminRoleGrantDeniedException.class);
	}

	@Test
	void revokesAccessRetainsHistoryAndAllowsALaterRegrant() {
		Tenant tenant = createTenant("revoke");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User target = createUser(tenant.id(), "target");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		AdminRoleCode support = AdminRoleCode.from("support");
		AdminRoleBinding first = this.roles.grantPermanent(tenant.id(), superAdmin.id(), target.id(), support,
				"Support rotation");

		AdminRoleBinding revoked = this.roles.revoke(tenant.id(), superAdmin.id(), target.id(), support);

		assertThat(revoked.id()).isEqualTo(first.id());
		assertThat(revoked.status()).isEqualTo(AdminRoleBindingStatus.REVOKED);
		assertThat(this.roles.findEffectivePermissions(tenant.id(), target.id())).isEmpty();
		AdminRoleBinding second = this.roles.grantPermanent(tenant.id(), superAdmin.id(), target.id(), support,
				"New support rotation");
		assertThat(second.id()).isNotEqualTo(first.id());
		assertThat(this.roles.findBindings(tenant.id(), target.id()))
			.extracting(AdminRoleBinding::status)
			.containsExactly(AdminRoleBindingStatus.REVOKED, AdminRoleBindingStatus.ACTIVE);
		assertThatThrownBy(() -> this.roles.bootstrapSuperAdmin(tenant.id(), target.id()))
			.isInstanceOf(AdminRoleBootstrapUnavailableException.class);
	}

	@Test
	void excludesExpiredAndInactivePrincipalsAndScopesEveryLookupToATenant() {
		Tenant tenant = createTenant("effective");
		Tenant other = createTenant("other");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User target = createUser(tenant.id(), "target");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		AdminRoleBinding jit = this.roles.grantJustInTime(tenant.id(), superAdmin.id(), target.id(),
				AdminRoleCode.from("auditor"), Instant.now().plusSeconds(3_600), "Incident review");
		this.jdbcClient.sql("""
				UPDATE admin_role_bindings
				SET expires_at = created_at + interval '1 microsecond'
				WHERE binding_id = :bindingId
				""").param("bindingId", jit.id().value()).update();

		assertThat(this.roles.findEffectivePermissions(tenant.id(), target.id())).isEmpty();
		assertThat(this.roles.findEffectivePermissions(other.id(), target.id())).isEmpty();
		assertThatThrownBy(() -> this.roles.grantPermanent(other.id(), superAdmin.id(), target.id(),
				AdminRoleCode.from("support"), "Cross tenant")).isInstanceOf(UserNotFoundException.class);
		AdminRoleBinding renewed = this.roles.grantJustInTime(tenant.id(), superAdmin.id(), target.id(),
				AdminRoleCode.from("auditor"), Instant.now().plusSeconds(3_600), "Renewed incident review");
		assertThat(renewed.id()).isNotEqualTo(jit.id());
		assertThat(this.roles.findBindings(tenant.id(), target.id()))
			.extracting(AdminRoleBinding::status)
			.containsExactly(AdminRoleBindingStatus.REVOKED, AdminRoleBindingStatus.ACTIVE);

		this.roles.grantPermanent(tenant.id(), superAdmin.id(), target.id(), AdminRoleCode.from("support"),
				"Support rotation");
		this.users.disable(tenant.id(), target.id());
		assertThat(this.roles.findEffectivePermissions(tenant.id(), target.id())).isEmpty();
		assertThat(this.roles.revoke(tenant.id(), superAdmin.id(), target.id(), AdminRoleCode.from("support"))
			.status()).isEqualTo(AdminRoleBindingStatus.REVOKED);
	}

	@Test
	void deniesActorsWithoutAssignmentPermissionAndRollsBackWithTheCaller() {
		Tenant tenant = createTenant("rollback");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User support = createUser(tenant.id(), "support");
		User target = createUser(tenant.id(), "target");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), support.id(), AdminRoleCode.from("support"),
				"Support rotation");

		assertThatThrownBy(() -> this.roles.grantPermanent(tenant.id(), support.id(), target.id(),
				AdminRoleCode.from("support"), "Unauthorized delegation"))
			.isInstanceOf(AdminRoleGrantDeniedException.class);

		transactionTemplate().executeWithoutResult(status -> {
			this.roles.grantPermanent(tenant.id(), superAdmin.id(), target.id(), AdminRoleCode.from("auditor"),
					"Rolled back");
			status.setRollbackOnly();
		});
		assertThat(this.roles.findActiveBinding(tenant.id(), target.id(), AdminRoleCode.from("auditor"))).isEmpty();
		assertThat(auditEventCount(tenant.id(), target.id(), "administration.role.granted", "auditor")).isZero();
	}

	@Test
	void auditsRoleGrantsAndRevocationsWithActorAndTarget() {
		Tenant tenant = createTenant("audit");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User target = createUser(tenant.id(), "target");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		AdminRoleCode role = AdminRoleCode.from("auditor");

		this.roles.grantPermanent(tenant.id(), superAdmin.id(), target.id(), role, "Compliance review");
		this.roles.revoke(tenant.id(), superAdmin.id(), target.id(), role);

		assertThat(this.jdbcClient.sql("""
				SELECT event_type || '|' || actor_user_id || '|' || user_id || '|' || (attributes ->> 'role')
				FROM audit_events
				WHERE tenant_id = :tenantId AND user_id = :userId
				  AND event_type IN ('administration.role.granted', 'administration.role.revoked')
				ORDER BY occurred_at, event_id
				""")
			.param("tenantId", tenant.id().value())
			.param("userId", target.id().value())
			.query(String.class)
			.list()).containsExactly(
					"administration.role.granted|" + superAdmin.id() + "|" + target.id() + "|auditor",
					"administration.role.revoked|" + superAdmin.id() + "|" + target.id() + "|auditor");
	}

	private int auditEventCount(TenantId tenantId, UserId userId, String type, String role) {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM audit_events
				WHERE tenant_id = :tenantId AND user_id = :userId AND event_type = :type
				  AND attributes ->> 'role' = :role
				""")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.param("type", type)
			.param("role", role)
			.query(Integer.class)
			.single();
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("admin-" + purpose + "-" + suffix,
				"Admin Role Tenant"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username("admin-" + purpose + "-" + suffix))));
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private Object attemptBootstrap(TenantId tenantId, UserId userId, CountDownLatch ready, CountDownLatch start)
			throws InterruptedException {
		ready.countDown();
		if (!start.await(5, TimeUnit.SECONDS)) {
			throw new IllegalStateException("Timed out waiting to start concurrent admin bootstrap");
		}
		try {
			return this.roles.bootstrapSuperAdmin(tenantId, userId);
		}
		catch (AdminRoleBootstrapUnavailableException exception) {
			return exception;
		}
	}

}
