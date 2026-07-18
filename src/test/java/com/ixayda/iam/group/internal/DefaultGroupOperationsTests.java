package com.ixayda.iam.group.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import org.junit.jupiter.api.Test;

class DefaultGroupOperationsTests {

	private static final GroupId GROUP_ID =
			new GroupId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f121"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final JdbcGroupRepository repository = mock(JdbcGroupRepository.class);

	private final TenantOperations tenants = mock(TenantOperations.class);

	private final GroupTimeSource timeSource = mock(GroupTimeSource.class);

	private final DefaultGroupOperations operations =
			new DefaultGroupOperations(this.repository, this.tenants, this.timeSource);

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

	private Group group(String displayName, GroupStatus status, long version, Instant updatedAt) {
		return new Group(GROUP_ID, TenantId.DEFAULT, displayName, status, version, CREATED_AT, updatedAt);
	}

	private Tenant activeTenant() {
		return new Tenant(TenantId.DEFAULT, "default", "Default", TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

}
