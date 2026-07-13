package com.ixayda.iam.organization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.ixayda.iam.organization.Organization;
import com.ixayda.iam.organization.OrganizationId;
import com.ixayda.iam.organization.OrganizationMembership;
import com.ixayda.iam.organization.OrganizationMembershipConcurrentUpdateException;
import com.ixayda.iam.organization.OrganizationMembershipNotActiveException;
import com.ixayda.iam.organization.OrganizationMembershipNotFoundException;
import com.ixayda.iam.organization.OrganizationMembershipStatus;
import com.ixayda.iam.organization.OrganizationOperations;
import com.ixayda.iam.organization.OrganizationStatus;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class DefaultOrganizationMembershipOperationsTests {

	private static final OrganizationId ORGANIZATION_ID =
			OrganizationId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d52");

	private static final OrganizationId OTHER_ORGANIZATION_ID =
			OrganizationId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d53");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d55");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final JdbcOrganizationMembershipRepository repository =
			mock(JdbcOrganizationMembershipRepository.class);

	private final TenantOperations tenants = mock(TenantOperations.class);

	private final OrganizationOperations organizations = mock(OrganizationOperations.class);

	private final UserOperations users = mock(UserOperations.class);

	private final OrganizationMembershipTimeSource timeSource = mock(OrganizationMembershipTimeSource.class);

	private final DefaultOrganizationMembershipOperations operations = new DefaultOrganizationMembershipOperations(
			this.repository, this.tenants, this.organizations, this.users, this.timeSource);

	@Test
	void addsAfterLockingTheOrganizationBeforeTheUser() {
		when(this.organizations.requireActiveForWrite(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(organization());
		when(this.users.requireActiveForWrite(TenantId.DEFAULT, USER_ID)).thenReturn(user());
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.empty());
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.insert(any(OrganizationMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));

		OrganizationMembership added = this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);

		assertThat(added).isEqualTo(activeMembership());
		InOrder order = inOrder(this.organizations, this.users, this.repository);
		order.verify(this.organizations).requireActiveForWrite(TenantId.DEFAULT, ORGANIZATION_ID);
		order.verify(this.users).requireActiveForWrite(TenantId.DEFAULT, USER_ID);
		order.verify(this.repository).find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
		order.verify(this.repository).insert(added);
	}

	@Test
	void returnsAnExistingActiveMembershipIdempotently() {
		OrganizationMembership active = activeMembership();
		stubActiveWriteParents();
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isSameAs(active);
		verify(this.repository, never()).insert(any());
		verify(this.repository, never()).update(any(), any());
		verifyNoInteractions(this.timeSource);
	}

	@Test
	void reactivatesARemovedMembership() {
		OrganizationMembership removed = removedMembership(1, CREATED_AT.plusSeconds(1));
		OrganizationMembership reactivated = removed.activate(CREATED_AT.plusSeconds(2));
		stubActiveWriteParents();
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.of(removed));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(2));
		when(this.repository.update(removed, reactivated)).thenReturn(reactivated);

		assertThat(this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isEqualTo(reactivated);
	}

	@Test
	void convergesAConcurrentFirstAdd() {
		OrganizationMembership active = activeMembership();
		stubActiveWriteParents();
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.thenReturn(Optional.empty())
			.thenReturn(Optional.of(active));
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.insert(any(OrganizationMembership.class)))
			.thenThrow(new OrganizationMembershipAlreadyExistsException(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID));

		assertThat(this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isSameAs(active);
		verify(this.repository, times(2)).find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
	}

	@Test
	void convergesAConcurrentReactivationThatReachedTheTargetStatus() {
		OrganizationMembership removed = removedMembership(1, CREATED_AT.plusSeconds(1));
		OrganizationMembership latest = removed.activate(CREATED_AT.plusSeconds(2));
		OrganizationMembershipConcurrentUpdateException conflict = conflict(removed);
		stubActiveWriteParents();
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.thenReturn(Optional.of(removed))
			.thenReturn(Optional.of(latest));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(2));
		when(this.repository.update(removed, latest)).thenThrow(conflict);

		assertThat(this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isSameAs(latest);
	}

	@Test
	void preservesAConcurrentReactivationConflictWhenTheTargetWasNotReached() {
		OrganizationMembership removed = removedMembership(1, CREATED_AT.plusSeconds(1));
		OrganizationMembership changed = removed.activate(CREATED_AT.plusSeconds(2));
		OrganizationMembership latest = removedMembership(3, CREATED_AT.plusSeconds(3));
		OrganizationMembershipConcurrentUpdateException conflict = conflict(removed);
		stubActiveWriteParents();
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.thenReturn(Optional.of(removed))
			.thenReturn(Optional.of(latest));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(2));
		when(this.repository.update(removed, changed)).thenThrow(conflict);

		assertThatThrownBy(() -> this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.isSameAs(conflict);
	}

	@Test
	void removesUsingOnlyTheTenantWriteGuard() {
		OrganizationMembership active = activeMembership();
		OrganizationMembership removed = active.remove(CREATED_AT.plusSeconds(1));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(tenant());
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.of(active));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.update(active, removed)).thenReturn(removed);

		assertThat(this.operations.removeMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isEqualTo(removed);
		verifyNoInteractions(this.organizations, this.users);
	}

	@Test
	void returnsAnExistingRemovalIdempotently() {
		OrganizationMembership removed = removedMembership(1, CREATED_AT.plusSeconds(1));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(tenant());
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.of(removed));

		assertThat(this.operations.removeMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isSameAs(removed);
		verify(this.repository, never()).update(any(), any());
		verifyNoInteractions(this.timeSource, this.organizations, this.users);
	}

	@Test
	void convergesAConcurrentRemoval() {
		OrganizationMembership active = activeMembership();
		OrganizationMembership removed = active.remove(CREATED_AT.plusSeconds(1));
		OrganizationMembershipConcurrentUpdateException conflict = conflict(active);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(tenant());
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.thenReturn(Optional.of(active))
			.thenReturn(Optional.of(removed));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.update(active, removed)).thenThrow(conflict);

		assertThat(this.operations.removeMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isSameAs(removed);
	}

	@Test
	void reportsAMissingMembershipWithItsCompositeIdentity() {
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(tenant());
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> this.operations.removeMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.isInstanceOf(OrganizationMembershipNotFoundException.class)
			.extracting("tenantId", "organizationId", "userId")
			.containsExactly(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
	}

	@Test
	void requiresEveryParentAndTheMembershipToBeActive() {
		OrganizationMembership active = activeMembership();
		when(this.organizations.requireActive(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(organization());
		when(this.users.requireActive(TenantId.DEFAULT, USER_ID)).thenReturn(user());
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.requireActiveMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).isSameAs(active);

		OrganizationMembership removed = active.remove(CREATED_AT.plusSeconds(1));
		when(this.repository.find(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID)).thenReturn(Optional.of(removed));
		assertThatThrownBy(() -> this.operations.requireActiveMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.isInstanceOf(OrganizationMembershipNotActiveException.class)
			.extracting("tenantId", "organizationId", "userId", "status")
			.containsExactly(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, OrganizationMembershipStatus.REMOVED);
	}

	@Test
	void rejectsUnexpectedLifecycleGuardResults() {
		Organization unexpected = new Organization(OTHER_ORGANIZATION_ID, TenantId.DEFAULT, "other", "Other",
				OrganizationStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
		when(this.organizations.requireActiveForWrite(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(unexpected);
		when(this.users.requireActiveForWrite(TenantId.DEFAULT, USER_ID)).thenReturn(user());

		assertThatThrownBy(() -> this.operations.addMember(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("Membership lifecycle guards returned a different organization or user");
		verifyNoInteractions(this.repository, this.timeSource);
	}

	@Test
	void rejectsNullInputBeforeTouchingMembershipState() {
		assertThatThrownBy(() -> this.operations.addMember(null, ORGANIZATION_ID, USER_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.removeMember(TenantId.DEFAULT, null, USER_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.findMembership(TenantId.DEFAULT, ORGANIZATION_ID, null))
			.isInstanceOf(NullPointerException.class);
		verifyNoInteractions(this.tenants, this.organizations, this.users, this.repository, this.timeSource);
	}

	private void stubActiveWriteParents() {
		when(this.organizations.requireActiveForWrite(TenantId.DEFAULT, ORGANIZATION_ID)).thenReturn(organization());
		when(this.users.requireActiveForWrite(TenantId.DEFAULT, USER_ID)).thenReturn(user());
	}

	private Tenant tenant() {
		return new Tenant(TenantId.DEFAULT, "default", "Default", TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

	private Organization organization() {
		return new Organization(ORGANIZATION_ID, TenantId.DEFAULT, "engineering", "Engineering",
				OrganizationStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

	private User user() {
		return new User(USER_ID, TenantId.DEFAULT, List.of(LoginIdentifier.username("alice")), UserStatus.ACTIVE, 0,
				CREATED_AT, CREATED_AT, null);
	}

	private OrganizationMembership activeMembership() {
		return OrganizationMembership.active(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, CREATED_AT);
	}

	private OrganizationMembership removedMembership(long version, Instant updatedAt) {
		return new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.REMOVED, version, CREATED_AT, updatedAt);
	}

	private OrganizationMembershipConcurrentUpdateException conflict(OrganizationMembership membership) {
		return new OrganizationMembershipConcurrentUpdateException(membership.tenantId(), membership.organizationId(),
				membership.userId(), membership.version());
	}

}
