package com.ixayda.iam.organization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.organization.Organization;
import com.ixayda.iam.organization.OrganizationAlreadyExistsException;
import com.ixayda.iam.organization.OrganizationConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationStatus;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcOrganizationRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cd1"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final List<OrganizationId> organizationsToDelete = new ArrayList<>();

	@Autowired
	private JdbcOrganizationRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createSecondTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'second-organization-tenant', 'Second Organization Tenant')
				""").param("tenantId", SECOND_TENANT_ID.value()).update();
	}

	@AfterEach
	void deleteFixtures() {
		this.organizationsToDelete.forEach(organizationId -> this.jdbcClient
			.sql("DELETE FROM organizations WHERE organization_id = :organizationId")
			.param("organizationId", organizationId.value())
			.update());
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void storesAndFindsAnOrganizationWithinItsTenant() {
		Organization organization = organization(TenantId.DEFAULT, "engineering", "Engineering");

		assertThat(this.repository.insert(organization)).isEqualTo(organization);
		assertThat(this.repository.findById(TenantId.DEFAULT, organization.id())).contains(organization);
		assertThat(this.repository.findBySlug(TenantId.DEFAULT, organization.slug())).contains(organization);
		assertThat(this.repository.findById(SECOND_TENANT_ID, organization.id())).isEmpty();
		assertThat(this.repository.findBySlug(SECOND_TENANT_ID, organization.slug())).isEmpty();
	}

	@Test
	void scopesSlugUniquenessToATenant() {
		Organization first = organization(TenantId.DEFAULT, "platform", "Platform");
		Organization second = organization(SECOND_TENANT_ID, "platform", "Platform");
		Organization duplicate = organization(TenantId.DEFAULT, "platform", "Duplicate");

		this.repository.insert(first);
		this.repository.insert(second);

		assertThat(this.repository.findBySlug(TenantId.DEFAULT, "platform")).contains(first);
		assertThat(this.repository.findBySlug(SECOND_TENANT_ID, "platform")).contains(second);
		assertThatThrownBy(() -> this.repository.insert(duplicate))
			.isInstanceOf(OrganizationAlreadyExistsException.class)
			.extracting("tenantId", "slug")
			.containsExactly(TenantId.DEFAULT, "platform");
	}

	@Test
	void updatesAStatusUsingTenantScopedOptimisticLocking() {
		Organization current = organization(TenantId.DEFAULT, "operations", "Operations");
		this.repository.insert(current);
		Organization disabled = current.disable(current.updatedAt().plusSeconds(1));

		assertThat(this.repository.updateStatus(current, disabled)).isEqualTo(disabled);
		assertThat(this.repository.findById(TenantId.DEFAULT, current.id())).contains(disabled);
		assertThatThrownBy(() -> this.repository.updateStatus(current, disabled))
			.isInstanceOf(OrganizationConcurrentUpdateException.class)
			.extracting("tenantId", "organizationId", "expectedVersion")
			.containsExactly(TenantId.DEFAULT, current.id(), 0L);
	}

	@Test
	void rejectsChangingTenantOwnershipDuringAStatusUpdate() {
		Organization current = organization(TenantId.DEFAULT, "security", "Security");
		Organization moved = new Organization(current.id(), SECOND_TENANT_ID, current.slug(), current.displayName(),
				OrganizationStatus.DISABLED, 1, current.createdAt(), current.updatedAt().plusSeconds(1));

		assertThatThrownBy(() -> this.repository.updateStatus(current, moved))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void doesNotUpdateAnExistingOrganizationThroughAnotherTenant() {
		Organization stored = organization(TenantId.DEFAULT, "identity", "Identity");
		this.repository.insert(stored);
		Organization forgedCurrent = new Organization(stored.id(), SECOND_TENANT_ID, stored.slug(), stored.displayName(),
				stored.status(), stored.version(), stored.createdAt(), stored.updatedAt());
		Organization forgedChange = forgedCurrent.disable(forgedCurrent.updatedAt().plusSeconds(1));

		assertThatThrownBy(() -> this.repository.updateStatus(forgedCurrent, forgedChange))
			.isInstanceOf(OrganizationConcurrentUpdateException.class);
		assertThat(this.repository.findById(TenantId.DEFAULT, stored.id())).contains(stored);
	}

	@Test
	void rejectsAStatusUpdateWithARegressingTimestamp() {
		OrganizationId organizationId = OrganizationId.random();
		Organization current = new Organization(organizationId, TenantId.DEFAULT, "time", "Time",
				OrganizationStatus.ACTIVE, 0, CREATED_AT, CREATED_AT.plusSeconds(60));
		Organization changed = new Organization(organizationId, TenantId.DEFAULT, "time", "Time",
				OrganizationStatus.DISABLED, 1, CREATED_AT, CREATED_AT.plusSeconds(30));

		assertThatThrownBy(() -> this.repository.updateStatus(current, changed))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void requiresAReadWriteTransactionForTheSharedOrganizationLock() {
		Organization organization = organization(TenantId.DEFAULT, "shared-lock", "Shared Lock");
		this.repository.insert(organization);

		assertThatThrownBy(() -> this.repository.findByIdForShare(TenantId.DEFAULT, organization.id()))
			.isInstanceOf(IllegalTransactionStateException.class);
		TransactionTemplate readOnly = new TransactionTemplate(this.transactionManager);
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly
			.execute(status -> this.repository.findByIdForShare(TenantId.DEFAULT, organization.id())))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Organization write requires an existing read-write transaction");

		TransactionTemplate readWrite = new TransactionTemplate(this.transactionManager);
		Optional<Organization> locked = readWrite
			.execute(status -> this.repository.findByIdForShare(TenantId.DEFAULT, organization.id()));
		assertThat(locked).contains(organization);
	}

	private Organization organization(TenantId tenantId, String slug, String displayName) {
		Organization organization = new Organization(OrganizationId.random(), tenantId, slug, displayName,
				OrganizationStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
		this.organizationsToDelete.add(organization.id());
		return organization;
	}

}
