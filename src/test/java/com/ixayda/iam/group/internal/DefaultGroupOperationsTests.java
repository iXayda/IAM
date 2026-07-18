package com.ixayda.iam.group.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
import com.ixayda.iam.group.GroupNotFoundException;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class DefaultGroupOperationsTests {

	private static final GroupId GROUP_ID =
			new GroupId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f121"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final UserId FIRST_USER_ID =
			new UserId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f122"));

	private static final UserId SECOND_USER_ID =
			new UserId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f123"));

	private final JdbcGroupRepository repository = mock(JdbcGroupRepository.class);

	private final TenantOperations tenants = mock(TenantOperations.class);

	private final GroupTimeSource timeSource = mock(GroupTimeSource.class);

	private final JdbcGroupMembershipRepository memberships = mock(JdbcGroupMembershipRepository.class);

	private final UserOperations users = mock(UserOperations.class);

	private final DefaultGroupOperations operations =
			new DefaultGroupOperations(this.repository, this.tenants, this.timeSource, this.memberships, this.users);

	@Test
	void createsAfterAcquiringTheTenantWriteGuard() {
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.insert(any(Group.class))).thenAnswer(invocation -> invocation.getArgument(0));

		Group created = this.operations.create(TenantId.DEFAULT, new CreateGroupRequest("Engineering"));

		assertThat(created.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(created.displayName()).isEqualTo("Engineering");
		assertThat(created.status()).isEqualTo(GroupStatus.ACTIVE);
		assertThat(created.version()).isZero();
		verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
	}

	@Test
	void locksTheTenantBeforeUpdatingTheGroup() {
		Group current = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);
		Group changed = group("Platform", GroupStatus.ACTIVE, 1, CREATED_AT.plusSeconds(1));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForUpdate(TenantId.DEFAULT, GROUP_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.updateDisplayName(current, changed)).thenReturn(changed);

		assertThat(this.operations.updateDisplayName(TenantId.DEFAULT, GROUP_ID, 0, "Platform")).isEqualTo(changed);

		verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		verify(this.repository).findByIdForUpdate(TenantId.DEFAULT, GROUP_ID);
		verify(this.repository).updateDisplayName(current, changed);
	}

	@Test
	void preservesAMonotonicTimestampWhenTheClockMovesBackward() {
		Instant future = CREATED_AT.plusSeconds(60);
		Group current = group("Engineering", GroupStatus.ACTIVE, 0, future);
		Group changed = group("Platform", GroupStatus.ACTIVE, 1, future);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForUpdate(TenantId.DEFAULT, GROUP_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.updateDisplayName(current, changed)).thenReturn(changed);

		assertThat(this.operations.updateDisplayName(TenantId.DEFAULT, GROUP_ID, 0, "Platform")).isEqualTo(changed);
	}

	@Test
	void readsMembersOnlyWhenTheRepositoryFindsAnActiveGroup() {
		GroupMembership membership = membership(FIRST_USER_ID, CREATED_AT);
		when(this.memberships.findByActiveGroup(TenantId.DEFAULT, GROUP_ID))
			.thenReturn(Optional.of(Set.of(membership)))
			.thenReturn(Optional.empty());

		assertThat(this.operations.findMembers(TenantId.DEFAULT, GROUP_ID)).containsExactly(membership);
		assertThatThrownBy(() -> this.operations.findMembers(TenantId.DEFAULT, GROUP_ID))
			.isInstanceOf(GroupNotFoundException.class);
		verifyNoInteractions(this.repository, this.tenants, this.users, this.timeSource);
	}

	@Test
	void replacesMembersUsingTheStableLockAndWriteOrder() {
		Group current = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);
		Group changed = group("Engineering", GroupStatus.ACTIVE, 1, CREATED_AT.plusSeconds(1));
		LinkedHashSet<UserId> desired = new LinkedHashSet<>();
		desired.add(SECOND_USER_ID);
		desired.add(FIRST_USER_ID);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForUpdate(TenantId.DEFAULT, GROUP_ID)).thenReturn(Optional.of(current));
		when(this.memberships.findByGroup(TenantId.DEFAULT, GROUP_ID)).thenReturn(Set.of());
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.updateMembers(current, changed)).thenReturn(changed);

		assertThat(this.operations.replaceMembers(TenantId.DEFAULT, GROUP_ID, 0, desired)).isEqualTo(changed);

		InOrder order = inOrder(this.tenants, this.repository, this.users, this.memberships, this.timeSource);
		order.verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		order.verify(this.repository).findByIdForUpdate(TenantId.DEFAULT, GROUP_ID);
		order.verify(this.memberships).findByGroup(TenantId.DEFAULT, GROUP_ID);
		order.verify(this.users).recordMembershipChangeForWrite(TenantId.DEFAULT, FIRST_USER_ID);
		order.verify(this.users).recordMembershipChangeForWrite(TenantId.DEFAULT, SECOND_USER_ID);
		order.verify(this.timeSource).now();
		order.verify(this.memberships).replace(current, Set.of(), Set.copyOf(desired), CREATED_AT.plusSeconds(1));
		order.verify(this.repository).updateMembers(current, changed);
	}

	@Test
	void treatsAnEquivalentMemberSetAsANoOp() {
		Group current = group("Engineering", GroupStatus.ACTIVE, 4, CREATED_AT.plusSeconds(4));
		Set<GroupMembership> existing = Set.of(membership(FIRST_USER_ID, CREATED_AT));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForUpdate(TenantId.DEFAULT, GROUP_ID)).thenReturn(Optional.of(current));
		when(this.memberships.findByGroup(TenantId.DEFAULT, GROUP_ID)).thenReturn(existing);

		assertThat(this.operations.replaceMembers(TenantId.DEFAULT, GROUP_ID, 4, Set.of(FIRST_USER_ID)))
			.isSameAs(current);
		verify(this.users).requireNotDeletedForWrite(TenantId.DEFAULT, FIRST_USER_ID);
		verify(this.memberships, never()).replace(any(), any(), any(), any());
		verify(this.repository, never()).updateMembers(any(), any());
		verifyNoInteractions(this.timeSource);
	}

	@Test
	void clearsMembersBeforeSoftDeletingTheGroup() {
		Group current = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);
		Group deleted = group("Engineering", GroupStatus.DELETED, 1, CREATED_AT.plusSeconds(1));
		Set<GroupMembership> existing = Set.of(membership(FIRST_USER_ID, CREATED_AT));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForUpdate(TenantId.DEFAULT, GROUP_ID)).thenReturn(Optional.of(current));
		when(this.memberships.findByGroup(TenantId.DEFAULT, GROUP_ID)).thenReturn(existing);
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.delete(current, deleted)).thenReturn(deleted);

		assertThat(this.operations.delete(TenantId.DEFAULT, GROUP_ID, 0)).isEqualTo(deleted);
		InOrder order = inOrder(this.tenants, this.repository, this.memberships, this.users);
		order.verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		order.verify(this.repository).findByIdForUpdate(TenantId.DEFAULT, GROUP_ID);
		order.verify(this.memberships).findByGroup(TenantId.DEFAULT, GROUP_ID);
		order.verify(this.users).recordMembershipChangeForWrite(TenantId.DEFAULT, FIRST_USER_ID);
		order.verify(this.memberships).deleteByGroup(current);
		order.verify(this.repository).delete(current, deleted);
	}

	private Group group(String displayName, GroupStatus status, long version, Instant updatedAt) {
		return new Group(GROUP_ID, TenantId.DEFAULT, displayName, status, version, CREATED_AT, updatedAt);
	}

	private GroupMembership membership(UserId userId, Instant createdAt) {
		return new GroupMembership(TenantId.DEFAULT, GROUP_ID, userId, createdAt);
	}

	private Tenant activeTenant() {
		return new Tenant(TenantId.DEFAULT, "default", "Default", TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

}
