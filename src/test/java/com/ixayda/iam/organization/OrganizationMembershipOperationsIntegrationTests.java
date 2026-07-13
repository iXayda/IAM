package com.ixayda.iam.organization;

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
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class OrganizationMembershipOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<MembershipReference> membershipsToDelete = new ArrayList<>();

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<OrganizationReference> organizationsToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private OrganizationMembershipOperations memberships;

	@Autowired
	private OrganizationOperations organizations;

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
		this.membershipsToDelete.forEach(reference -> this.jdbcClient.sql("""
				DELETE FROM organization_memberships
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND user_id = :userId
				""")
			.param("tenantId", reference.tenantId().value())
			.param("organizationId", reference.organizationId().value())
			.param("userId", reference.userId().value())
			.update());
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
		});
		this.organizationsToDelete.forEach(reference -> this.jdbcClient.sql("""
				DELETE FROM organizations
				WHERE tenant_id = :tenantId AND organization_id = :organizationId
				""")
			.param("tenantId", reference.tenantId().value())
			.param("organizationId", reference.organizationId().value())
			.update());
		this.tenantsToDelete.reversed().forEach(tenantId -> this.jdbcClient
			.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void addsRemovesAndReactivatesAMembershipIdempotently() {
		Organization organization = createOrganization(TenantId.DEFAULT, "lifecycle");
		User user = createUser(TenantId.DEFAULT, "lifecycle");

		OrganizationMembership added = add(organization, user);
		assertThat(added.status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
		assertThat(added.version()).isZero();
		assertThat(this.memberships.addMember(TenantId.DEFAULT, organization.id(), user.id())).isEqualTo(added);
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, organization.id(), user.id())).contains(added);

		OrganizationMembership removed =
				this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id());
		assertThat(removed.status()).isEqualTo(OrganizationMembershipStatus.REMOVED);
		assertThat(removed.version()).isOne();
		assertThat(this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id())).isEqualTo(removed);

		OrganizationMembership reactivated =
				this.memberships.addMember(TenantId.DEFAULT, organization.id(), user.id());
		assertThat(reactivated.status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
		assertThat(reactivated.version()).isEqualTo(2);
		assertThat(reactivated.createdAt()).isEqualTo(added.createdAt());
	}

	@Test
	void requiresActiveParentsWhenAddingAMember() {
		Organization disabledOrganization = createOrganization(TenantId.DEFAULT, "disabled-organization");
		User activeUser = createUser(TenantId.DEFAULT, "active-user");
		this.organizations.disable(TenantId.DEFAULT, disabledOrganization.id());

		assertThatThrownBy(() -> this.memberships.addMember(TenantId.DEFAULT, disabledOrganization.id(), activeUser.id()))
			.isInstanceOf(OrganizationDisabledException.class);

		Organization activeOrganization = createOrganization(TenantId.DEFAULT, "active-organization");
		User disabledUser = createUser(TenantId.DEFAULT, "disabled-user");
		this.users.disable(TenantId.DEFAULT, disabledUser.id());

		assertThatThrownBy(() -> this.memberships.addMember(TenantId.DEFAULT, activeOrganization.id(), disabledUser.id()))
			.isInstanceOf(UserNotActiveException.class);
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, disabledOrganization.id(), activeUser.id()))
			.isEmpty();
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, activeOrganization.id(), disabledUser.id()))
			.isEmpty();
	}

	@Test
	void allowsRemovalAfterTheOrganizationAndUserAreDisabled() {
		Organization organization = createOrganization(TenantId.DEFAULT, "remove-disabled");
		User user = createUser(TenantId.DEFAULT, "remove-disabled");
		add(organization, user);
		this.organizations.disable(TenantId.DEFAULT, organization.id());
		this.users.disable(TenantId.DEFAULT, user.id());

		OrganizationMembership removed =
				this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id());

		assertThat(removed.status()).isEqualTo(OrganizationMembershipStatus.REMOVED);
	}

	@Test
	void requiresTheStoredRelationshipAndBothParentsToRemainActive() {
		Organization organization = createOrganization(TenantId.DEFAULT, "active-check");
		User user = createUser(TenantId.DEFAULT, "active-check");
		OrganizationMembership active = add(organization, user);

		assertThat(this.memberships.requireActiveMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isEqualTo(active);

		this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id());
		assertThatThrownBy(
				() -> this.memberships.requireActiveMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isInstanceOf(OrganizationMembershipNotActiveException.class);

		OrganizationMembership reactivated =
				this.memberships.addMember(TenantId.DEFAULT, organization.id(), user.id());
		this.users.lock(TenantId.DEFAULT, user.id());
		assertThatThrownBy(
				() -> this.memberships.requireActiveMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isInstanceOf(UserNotActiveException.class);
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, organization.id(), user.id()))
			.contains(reactivated);

		this.users.activate(TenantId.DEFAULT, user.id());
		this.organizations.disable(TenantId.DEFAULT, organization.id());
		assertThatThrownBy(
				() -> this.memberships.requireActiveMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isInstanceOf(OrganizationDisabledException.class);
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, organization.id(), user.id()))
			.contains(reactivated);

		this.organizations.activate(TenantId.DEFAULT, organization.id());
		assertThat(this.memberships.requireActiveMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isEqualTo(reactivated);
	}

	@Test
	void scopesMembershipsToATenant() {
		Organization organization = createOrganization(TenantId.DEFAULT, "isolation");
		User user = createUser(TenantId.DEFAULT, "isolation");
		OrganizationMembership active = add(organization, user);
		Tenant secondTenant = createTenant("isolation");

		assertThat(this.memberships.findMembership(secondTenant.id(), organization.id(), user.id())).isEmpty();
		assertThatThrownBy(
				() -> this.memberships.removeMember(secondTenant.id(), organization.id(), user.id()))
			.isInstanceOf(OrganizationMembershipNotFoundException.class);
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, organization.id(), user.id())).contains(active);
	}

	@Test
	void blocksLifecycleChecksAndWritesForADisabledTenantButPreservesRawLookup() {
		Tenant tenant = createTenant("disabled-tenant");
		Organization organization = createOrganization(tenant.id(), "disabled-tenant");
		User user = createUser(tenant.id(), "disabled-tenant");
		OrganizationMembership active = add(organization, user);
		this.tenants.disable(tenant.id());

		assertThatThrownBy(() -> this.memberships.addMember(tenant.id(), organization.id(), user.id()))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.memberships.removeMember(tenant.id(), organization.id(), user.id()))
			.isInstanceOf(TenantDisabledException.class);
		assertThatThrownBy(() -> this.memberships.requireActiveMember(tenant.id(), organization.id(), user.id()))
			.isInstanceOf(TenantDisabledException.class);
		assertThat(this.memberships.findMembership(tenant.id(), organization.id(), user.id())).contains(active);
	}

	@Test
	void participatesInTheCallerTransaction() {
		Organization organization = createOrganization(TenantId.DEFAULT, "rollback");
		User user = createUser(TenantId.DEFAULT, "rollback");

		transactionTemplate().executeWithoutResult(status -> {
			add(organization, user);
			status.setRollbackOnly();
		});
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, organization.id(), user.id())).isEmpty();

		OrganizationMembership active = add(organization, user);
		transactionTemplate().executeWithoutResult(status -> {
			this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id());
			status.setRollbackOnly();
		});
		assertThat(this.memberships.findMembership(TenantId.DEFAULT, organization.id(), user.id())).contains(active);
	}

	@Test
	void reportsAMissingMembershipWithItsCompositeIdentity() {
		Organization organization = createOrganization(TenantId.DEFAULT, "missing");
		User user = createUser(TenantId.DEFAULT, "missing");

		assertThatThrownBy(() -> this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isInstanceOf(OrganizationMembershipNotFoundException.class)
			.extracting("tenantId", "organizationId", "userId")
			.containsExactly(TenantId.DEFAULT, organization.id(), user.id());
		assertThatThrownBy(
				() -> this.memberships.requireActiveMember(TenantId.DEFAULT, organization.id(), user.id()))
			.isInstanceOf(OrganizationMembershipNotFoundException.class);
	}

	@Test
	void preservesAMonotonicTimestampWhenTheClockMovesBackward() {
		Organization organization = createOrganization(TenantId.DEFAULT, "future-time");
		User user = createUser(TenantId.DEFAULT, "future-time");
		OrganizationMembership active = add(organization, user);
		Instant future = active.updatedAt().plusSeconds(3_600);
		this.jdbcClient.sql("""
				UPDATE organization_memberships
				SET updated_at = :updatedAt
				WHERE tenant_id = :tenantId
				  AND organization_id = :organizationId
				  AND user_id = :userId
				""")
			.param("updatedAt", OffsetDateTime.ofInstant(future, ZoneOffset.UTC))
			.param("tenantId", TenantId.DEFAULT.value())
			.param("organizationId", organization.id().value())
			.param("userId", user.id().value())
			.update();

		OrganizationMembership removed =
				this.memberships.removeMember(TenantId.DEFAULT, organization.id(), user.id());

		assertThat(removed.updatedAt()).isEqualTo(future);
	}

	private OrganizationMembership add(Organization organization, User user) {
		OrganizationMembership membership =
				this.memberships.addMember(organization.tenantId(), organization.id(), user.id());
		this.membershipsToDelete.add(new MembershipReference(organization.tenantId(), organization.id(), user.id()));
		return membership;
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("membership-" + purpose + "-" + suffix,
				"Membership Tenant"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private Organization createOrganization(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Organization organization = this.organizations.create(tenantId,
				new CreateOrganizationRequest("membership-" + purpose + "-" + suffix, "Membership Organization"));
		this.organizationsToDelete.add(new OrganizationReference(tenantId, organization.id()));
		return organization;
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		User user = this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username("membership-" + purpose + "-" + suffix))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		return user;
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private record MembershipReference(TenantId tenantId, OrganizationId organizationId, UserId userId) {
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

	private record OrganizationReference(TenantId tenantId, OrganizationId organizationId) {
	}

}
