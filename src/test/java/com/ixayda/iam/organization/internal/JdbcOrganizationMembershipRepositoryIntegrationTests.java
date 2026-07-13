package com.ixayda.iam.organization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationMembership;
import com.ixayda.iam.organization.OrganizationMembershipStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcOrganizationMembershipRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			TenantId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d51");

	private static final OrganizationId ORGANIZATION_ID =
			OrganizationId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d52");

	private static final OrganizationId SECOND_ORGANIZATION_ID =
			OrganizationId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d53");

	private static final OrganizationId SAME_TENANT_ORGANIZATION_ID =
			OrganizationId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d54");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d55");

	private static final UserId SECOND_USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d56");

	private static final UserId SAME_TENANT_USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d57");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Autowired
	private JdbcOrganizationMembershipRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createParents() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'membership-store-tenant', 'Membership Store Tenant')
				""")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
		insertOrganization(TenantId.DEFAULT, ORGANIZATION_ID, "membership-store");
		insertOrganization(TenantId.DEFAULT, SAME_TENANT_ORGANIZATION_ID, "membership-store-same");
		insertOrganization(SECOND_TENANT_ID, SECOND_ORGANIZATION_ID, "membership-store-second");
		insertUser(TenantId.DEFAULT, USER_ID);
		insertUser(TenantId.DEFAULT, SAME_TENANT_USER_ID);
		insertUser(SECOND_TENANT_ID, SECOND_USER_ID);
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("""
				DELETE FROM organization_memberships
				WHERE organization_id IN (:organizationId, :sameTenantOrganizationId, :secondOrganizationId)
				""")
			.param("organizationId", ORGANIZATION_ID.value())
			.param("sameTenantOrganizationId", SAME_TENANT_ORGANIZATION_ID.value())
			.param("secondOrganizationId", SECOND_ORGANIZATION_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id IN (:userId, :sameTenantUserId, :secondUserId)")
			.param("userId", USER_ID.value())
			.param("sameTenantUserId", SAME_TENANT_USER_ID.value())
			.param("secondUserId", SECOND_USER_ID.value())
			.update();
		this.jdbcClient.sql("""
				DELETE FROM organizations
				WHERE organization_id IN (:organizationId, :sameTenantOrganizationId, :secondOrganizationId)
				""")
			.param("organizationId", ORGANIZATION_ID.value())
			.param("sameTenantOrganizationId", SAME_TENANT_ORGANIZATION_ID.value())
			.param("secondOrganizationId", SECOND_ORGANIZATION_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void storesAndFindsTenantScopedMemberships() {
		OrganizationMembership first = membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
		OrganizationMembership second = membership(SECOND_TENANT_ID, SECOND_ORGANIZATION_ID, SECOND_USER_ID);

		assertThat(insert(first)).isSameAs(first);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(first);
		assertThat(this.repository.find(SECOND_TENANT_ID, ORGANIZATION_ID, USER_ID)).isEmpty();
		assertThat(this.repository.find(TenantId.DEFAULT, SAME_TENANT_ORGANIZATION_ID, USER_ID)).isEmpty();
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, SAME_TENANT_USER_ID)).isEmpty();

		insert(second);
		assertThat(this.repository.find(SECOND_TENANT_ID, SECOND_ORGANIZATION_ID, SECOND_USER_ID)).contains(second);
	}

	@Test
	void rejectsDuplicatesWithoutAbortingTheCallerTransaction() {
		OrganizationMembership first = membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
		OrganizationMembership duplicate = OrganizationMembership.active(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				CREATED_AT.plusSeconds(1));

		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(first);
			assertThatThrownBy(() -> this.repository.insert(duplicate))
				.isInstanceOf(OrganizationMembershipAlreadyExistsException.class)
				.extracting("tenantId", "organizationId", "userId")
				.containsExactly(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
			assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(first);
		});

		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(first);
	}

	@Test
	void changesStatusUsingTenantScopedOptimisticLocking() {
		OrganizationMembership current = insert(membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));
		OrganizationMembership removed = current.remove(CREATED_AT.plusSeconds(1));

		assertThat(update(current, removed)).isSameAs(removed);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(removed);
		assertThatThrownBy(() -> update(current, removed))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class)
			.extracting("tenantId", "organizationId", "userId", "expectedVersion")
			.containsExactly(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, 0L);

		OrganizationMembership reactivated = removed.activate(CREATED_AT.plusSeconds(2));
		assertThat(update(removed, reactivated)).isSameAs(reactivated);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(reactivated);
	}

	@Test
	void doesNotUpdateAMembershipThroughAnotherTenant() {
		OrganizationMembership stored = insert(membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));
		OrganizationMembership forged = membership(SECOND_TENANT_ID, ORGANIZATION_ID, USER_ID);

		assertThatThrownBy(() -> update(forged, forged.remove(CREATED_AT.plusSeconds(1))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(stored);
	}

	@Test
	void doesNotUpdateAnotherOrganizationsMembershipInTheSameTenant() {
		OrganizationMembership stored = insert(membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));
		OrganizationMembership forged = membership(TenantId.DEFAULT, SAME_TENANT_ORGANIZATION_ID, USER_ID);

		assertThatThrownBy(() -> update(forged, forged.remove(CREATED_AT.plusSeconds(1))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(stored);
	}

	@Test
	void doesNotUpdateAnotherUsersMembershipInTheSameTenant() {
		OrganizationMembership stored = insert(membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));
		OrganizationMembership forged = membership(TenantId.DEFAULT, ORGANIZATION_ID, SAME_TENANT_USER_ID);

		assertThatThrownBy(() -> update(forged, forged.remove(CREATED_AT.plusSeconds(1))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(stored);
	}

	@Test
	void comparesTheCompleteExpectedStoredState() {
		OrganizationMembership stored = insert(membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));
		OrganizationMembership forgedCreation = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT.minusSeconds(1), CREATED_AT);
		OrganizationMembership forgedUpdate = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT.plusSeconds(1));
		OrganizationMembership forgedStatus = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.REMOVED, 0, CREATED_AT, CREATED_AT);
		OrganizationMembership forgedVersion = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 1, CREATED_AT, CREATED_AT);

		assertThatThrownBy(() -> update(forgedCreation, forgedCreation.remove(CREATED_AT.plusSeconds(2))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThatThrownBy(() -> update(forgedUpdate, forgedUpdate.remove(CREATED_AT.plusSeconds(2))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThatThrownBy(() -> update(forgedStatus, forgedStatus.activate(CREATED_AT.plusSeconds(2))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThatThrownBy(() -> update(forgedVersion, forgedVersion.remove(CREATED_AT.plusSeconds(2))))
			.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(stored);
	}

	@Test
	void keepsTheCallerTransactionUsableAfterAConcurrentUpdate() {
		OrganizationMembership current = insert(membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));
		OrganizationMembership removed = current.remove(CREATED_AT.plusSeconds(1));
		update(current, removed);

		OrganizationMembership latest = transactionTemplate().execute(status -> {
			assertThatThrownBy(() -> this.repository.update(current, removed))
				.isInstanceOf(OrganizationMembershipConcurrentUpdateException.class);
			return this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID).orElseThrow();
		});

		assertThat(latest).isEqualTo(removed);
	}

	@Test
	void participatesInCallerRollback() {
		OrganizationMembership initial = membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
		transactionTemplate().executeWithoutResult(status -> {
			this.repository.insert(initial);
			status.setRollbackOnly();
		});
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isEmpty();

		insert(initial);
		OrganizationMembership removed = initial.remove(CREATED_AT.plusSeconds(1));
		transactionTemplate().executeWithoutResult(status -> {
			this.repository.update(initial, removed);
			status.setRollbackOnly();
		});
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(initial);
	}

	@Test
	void requiresAnExistingReadWriteTransaction() {
		OrganizationMembership initial = membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);

		assertThatThrownBy(() -> this.repository.insert(initial))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = transactionTemplate();
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.insert(initial)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Organization membership write requires an existing read-write transaction");

		insert(initial);
		OrganizationMembership removed = initial.remove(CREATED_AT.plusSeconds(1));
		assertThatThrownBy(() -> this.repository.update(initial, removed))
			.isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> readOnly.execute(status -> this.repository.update(initial, removed)))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Organization membership write requires an existing read-write transaction");
		assertThat(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).contains(initial);
	}

	@Test
	void rejectsInvalidInsertAndUpdateShapes() {
		OrganizationMembership current = membership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
		OrganizationMembership invalidInitialStatus = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID,
				USER_ID, OrganizationMembershipStatus.REMOVED, 0, CREATED_AT, CREATED_AT);
		OrganizationMembership invalidInitialVersion = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID,
				USER_ID, OrganizationMembershipStatus.ACTIVE, 1, CREATED_AT, CREATED_AT);
		OrganizationMembership delayedInitial = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT.plusSeconds(1));
		OrganizationMembership changedTenant = new OrganizationMembership(SECOND_TENANT_ID, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.REMOVED, 1, CREATED_AT, CREATED_AT.plusSeconds(1));
		OrganizationMembership changedOrganization = new OrganizationMembership(TenantId.DEFAULT,
				SAME_TENANT_ORGANIZATION_ID, USER_ID, OrganizationMembershipStatus.REMOVED, 1, CREATED_AT,
				CREATED_AT.plusSeconds(1));
		OrganizationMembership changedUser = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID,
				SAME_TENANT_USER_ID, OrganizationMembershipStatus.REMOVED, 1, CREATED_AT,
				CREATED_AT.plusSeconds(1));
		OrganizationMembership sameStatus = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 1, CREATED_AT, CREATED_AT.plusSeconds(1));
		OrganizationMembership skippedVersion = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.REMOVED, 2, CREATED_AT, CREATED_AT.plusSeconds(1));
		OrganizationMembership changedCreation = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.REMOVED, 1, CREATED_AT.minusSeconds(1), CREATED_AT.plusSeconds(1));
		OrganizationMembership laterCurrent = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT.plusSeconds(2));
		OrganizationMembership backwardUpdate = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.REMOVED, 1, CREATED_AT, CREATED_AT.plusSeconds(1));

		assertThatThrownBy(() -> insert(invalidInitialStatus)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> insert(invalidInitialVersion)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> insert(delayedInitial)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedTenant)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedOrganization)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedUser)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, sameStatus)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, skippedVersion)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, changedCreation)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(laterCurrent, backwardUpdate)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> update(current, current)).isInstanceOf(IllegalArgumentException.class);
	}

	private OrganizationMembership membership(TenantId tenantId, OrganizationId organizationId, UserId userId) {
		return OrganizationMembership.active(tenantId, organizationId, userId, CREATED_AT);
	}

	private OrganizationMembership insert(OrganizationMembership membership) {
		return transactionTemplate().execute(status -> this.repository.insert(membership));
	}

	private OrganizationMembership update(OrganizationMembership current, OrganizationMembership changed) {
		return transactionTemplate().execute(status -> this.repository.update(current, changed));
	}

	private void insertOrganization(TenantId tenantId, OrganizationId organizationId, String slug) {
		this.jdbcClient.sql("""
				INSERT INTO organizations (tenant_id, organization_id, slug, display_name)
				VALUES (:tenantId, :organizationId, :slug, 'Membership Store Organization')
				""")
			.param("tenantId", tenantId.value())
			.param("organizationId", organizationId.value())
			.param("slug", slug)
			.update();
	}

	private void insertUser(TenantId tenantId, UserId userId) {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", tenantId.value())
			.param("userId", userId.value())
			.update();
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

}
