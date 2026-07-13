package com.ixayda.iam.organization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.organization.CreateOrganizationRequest;
import com.ixayda.iam.organization.Organization;
import com.ixayda.iam.organization.OrganizationConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationStatus;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class DefaultOrganizationOperationsTests {

	private static final OrganizationId ORGANIZATION_ID =
			new OrganizationId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc2"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final JdbcOrganizationRepository repository = mock(JdbcOrganizationRepository.class);

	private final TenantOperations tenants = mock(TenantOperations.class);

	private final OrganizationTimeSource timeSource = mock(OrganizationTimeSource.class);

	private final DefaultOrganizationOperations operations =
			new DefaultOrganizationOperations(this.repository, this.tenants, this.timeSource);

	@Test
	void requiresAnActiveTenantBeforeCreatingAnOrganization() {
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.insert(any(Organization.class))).thenAnswer(invocation -> invocation.getArgument(0));

		Organization created =
				this.operations.create(TenantId.DEFAULT, new CreateOrganizationRequest("engineering", "Engineering"));

		assertThat(created.tenantId()).isEqualTo(TenantId.DEFAULT);
		verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
	}

	@Test
	void usesTheTenantWriteGuardWhenActivatingAnOrganization() {
		Organization disabled = organization(OrganizationStatus.DISABLED, 1, CREATED_AT);
		Organization active = organization(OrganizationStatus.ACTIVE, 2, CREATED_AT.plusSeconds(1));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(Optional.of(disabled));
		when(this.repository.updateStatus(disabled, active)).thenReturn(active);
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThat(this.operations.activate(TenantId.DEFAULT, ORGANIZATION_ID)).isEqualTo(active);
		verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
	}

	@Test
	void usesANonLockingTenantCheckWhenReadingAnActiveOrganization() {
		Organization active = organization(OrganizationStatus.ACTIVE, 0, CREATED_AT);
		when(this.tenants.requireActive(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.requireActive(TenantId.DEFAULT, ORGANIZATION_ID)).isEqualTo(active);
		verify(this.tenants).requireActive(TenantId.DEFAULT);
	}

	@Test
	void locksTheTenantBeforeTheOrganizationForACoordinatedWrite() {
		Organization active = organization(OrganizationStatus.ACTIVE, 0, CREATED_AT);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForShare(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.requireActiveForWrite(TenantId.DEFAULT, ORGANIZATION_ID)).isEqualTo(active);

		InOrder order = inOrder(this.tenants, this.repository);
		order.verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		order.verify(this.repository).findByIdForShare(TenantId.DEFAULT, ORGANIZATION_ID);
	}

	@Test
	void returnsTheLatestOrganizationWhenAConcurrentRequestReachedTheTargetStatus() {
		Organization active = organization(OrganizationStatus.ACTIVE, 0, CREATED_AT);
		Organization latest = organization(OrganizationStatus.DISABLED, 3, CREATED_AT.plusSeconds(3));
		OrganizationConcurrentUpdateException conflict =
				new OrganizationConcurrentUpdateException(TenantId.DEFAULT, ORGANIZATION_ID, 0);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, ORGANIZATION_ID))
			.thenReturn(Optional.of(active))
			.thenReturn(Optional.of(latest));
		when(this.repository.updateStatus(any(Organization.class), any(Organization.class))).thenThrow(conflict);
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThat(this.operations.disable(TenantId.DEFAULT, ORGANIZATION_ID)).isEqualTo(latest);
		verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		verify(this.repository, times(2)).findById(TenantId.DEFAULT, ORGANIZATION_ID);
	}

	@Test
	void preservesTheConflictWhenTheConcurrentRequestDidNotReachTheTargetStatus() {
		Organization active = organization(OrganizationStatus.ACTIVE, 0, CREATED_AT);
		OrganizationConcurrentUpdateException conflict =
				new OrganizationConcurrentUpdateException(TenantId.DEFAULT, ORGANIZATION_ID, 0);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(Optional.of(active));
		when(this.repository.updateStatus(any(Organization.class), any(Organization.class))).thenThrow(conflict);
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThatThrownBy(() -> this.operations.disable(TenantId.DEFAULT, ORGANIZATION_ID)).isSameAs(conflict);
	}

	@Test
	void preservesAMonotonicTimestampWhenTheClockMovesBackward() {
		Instant storedTime = CREATED_AT.plusSeconds(60);
		Organization active = organization(OrganizationStatus.ACTIVE, 0, storedTime);
		Organization disabled = organization(OrganizationStatus.DISABLED, 1, storedTime);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(Optional.of(active));
		when(this.repository.updateStatus(active, disabled)).thenReturn(disabled);
		when(this.timeSource.now()).thenReturn(CREATED_AT);

		assertThat(this.operations.disable(TenantId.DEFAULT, ORGANIZATION_ID)).isEqualTo(disabled);
		verify(this.repository).updateStatus(active, disabled);
	}

	private Organization organization(OrganizationStatus status, long version, Instant updatedAt) {
		return new Organization(ORGANIZATION_ID, TenantId.DEFAULT, "engineering", "Engineering", status, version,
				CREATED_AT, updatedAt);
	}

	private Tenant activeTenant() {
		return new Tenant(TenantId.DEFAULT, "default", "Default", TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

}
