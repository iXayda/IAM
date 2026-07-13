package com.ixayda.iam.user.internal;

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
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserConcurrentUpdateException;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;

class DefaultUserOperationsTests {

	private static final UserId USER_ID =
			new UserId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc5"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final LoginIdentifier USERNAME = LoginIdentifier.username("alice");

	private final JdbcUserRepository repository = mock(JdbcUserRepository.class);

	private final TenantOperations tenants = mock(TenantOperations.class);

	private final UserTimeSource timeSource = mock(UserTimeSource.class);

	private final DefaultUserOperations operations =
			new DefaultUserOperations(this.repository, this.tenants, this.timeSource);

	@Test
	void createsAUserAfterAcquiringTheTenantWriteGuard() {
		CreateUserRequest request = new CreateUserRequest(List.of(USERNAME));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.insert(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

		User created = this.operations.create(TenantId.DEFAULT, request);

		assertThat(created.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(created.identifiers()).containsExactly(USERNAME);
		assertThat(created.status()).isEqualTo(UserStatus.ACTIVE);
		assertThat(created.version()).isZero();
		assertThat(created.createdAt()).isEqualTo(CREATED_AT);
		assertThat(created.updatedAt()).isEqualTo(CREATED_AT);
		assertThat(created.lastLoginAt()).isNull();
		InOrder order = inOrder(this.tenants, this.repository);
		order.verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		order.verify(this.repository).insert(created);
	}

	@Test
	void delegatesTenantScopedQueriesWithoutAnActiveTenantCheck() {
		User user = user(UserStatus.ACTIVE, 0, CREATED_AT);
		LoginKey loginKey = USERNAME.loginKey();
		when(this.repository.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(user));
		when(this.repository.findByLogin(TenantId.DEFAULT, loginKey)).thenReturn(Optional.of(user));

		assertThat(this.operations.findById(TenantId.DEFAULT, USER_ID)).contains(user);
		assertThat(this.operations.findByLogin(TenantId.DEFAULT, loginKey)).contains(user);
		verifyNoInteractions(this.tenants);
	}

	@ParameterizedTest
	@EnumSource(value = UserStatus.class, names = "ACTIVE", mode = EnumSource.Mode.EXCLUDE)
	void rejectsInactiveUsers(UserStatus status) {
		User user = user(status, 0, CREATED_AT);
		when(this.tenants.requireActive(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> this.operations.requireActive(TenantId.DEFAULT, USER_ID))
			.isInstanceOf(UserNotActiveException.class)
			.extracting("tenantId", "userId", "status")
			.containsExactly(TenantId.DEFAULT, USER_ID, status);
		verify(this.tenants).requireActive(TenantId.DEFAULT);
	}

	@Test
	void acquiresTenantAndUserWriteGuardsInOrder() {
		User active = user(UserStatus.ACTIVE, 0, CREATED_AT);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForShare(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.requireActiveForWrite(TenantId.DEFAULT, USER_ID)).isEqualTo(active);
		InOrder order = inOrder(this.tenants, this.repository);
		order.verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		order.verify(this.repository).findByIdForShare(TenantId.DEFAULT, USER_ID);
	}

	@Test
	void acquiresTenantAndExclusiveUserGuardsInOrder() {
		User active = user(UserStatus.ACTIVE, 0, CREATED_AT);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.requireActiveForUpdate(TenantId.DEFAULT, USER_ID)).isEqualTo(active);
		InOrder order = inOrder(this.tenants, this.repository);
		order.verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		order.verify(this.repository).findByIdForUpdate(TenantId.DEFAULT, USER_ID);
	}

	@ParameterizedTest
	@EnumSource(value = UserStatus.class, names = "ACTIVE", mode = EnumSource.Mode.EXCLUDE)
	void rejectsInactiveUsersForWrite(UserStatus status) {
		User user = user(status, 0, CREATED_AT);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findByIdForShare(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> this.operations.requireActiveForWrite(TenantId.DEFAULT, USER_ID))
			.isInstanceOf(UserNotActiveException.class)
			.extracting("tenantId", "userId", "status")
			.containsExactly(TenantId.DEFAULT, USER_ID, status);
	}

	@ParameterizedTest
	@EnumSource(UserStatus.class)
	void usesTheTenantWriteGuardForEveryStatusCommand(UserStatus target) {
		User current = user(sourceFor(target), 0, CREATED_AT);
		User changed = transition(current, target, CREATED_AT.plusSeconds(1));
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.updateStatus(current, changed)).thenReturn(changed);

		assertThat(changeStatus(target)).isEqualTo(changed);
		verify(this.tenants).requireActiveForWrite(TenantId.DEFAULT);
		verify(this.repository).updateStatus(current, changed);
	}

	@Test
	void avoidsAWriteWhenTheUserAlreadyHasTheTargetStatus() {
		User disabled = user(UserStatus.DISABLED, 3, CREATED_AT);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(disabled));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThat(this.operations.disable(TenantId.DEFAULT, USER_ID)).isSameAs(disabled);
		verify(this.repository, never()).updateStatus(any(), any());
	}

	@Test
	void returnsTheLatestUserWhenAConcurrentRequestReachedTheTargetStatus() {
		User active = user(UserStatus.ACTIVE, 0, CREATED_AT);
		User latest = user(UserStatus.DISABLED, 3, CREATED_AT.plusSeconds(3));
		UserConcurrentUpdateException conflict =
				new UserConcurrentUpdateException(TenantId.DEFAULT, USER_ID, 0);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID))
			.thenReturn(Optional.of(active))
			.thenReturn(Optional.of(latest));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.updateStatus(any(), any())).thenThrow(conflict);

		assertThat(this.operations.disable(TenantId.DEFAULT, USER_ID)).isEqualTo(latest);
	}

	@Test
	void preservesAConflictWhenTheConcurrentRequestReachedAnotherStatus() {
		User active = user(UserStatus.ACTIVE, 0, CREATED_AT);
		User latest = user(UserStatus.LOCKED, 1, CREATED_AT.plusSeconds(1));
		UserConcurrentUpdateException conflict =
				new UserConcurrentUpdateException(TenantId.DEFAULT, USER_ID, 0);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID))
			.thenReturn(Optional.of(active))
			.thenReturn(Optional.of(latest));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.updateStatus(any(), any())).thenThrow(conflict);

		assertThatThrownBy(() -> this.operations.disable(TenantId.DEFAULT, USER_ID)).isSameAs(conflict);
	}

	@Test
	void preservesAMonotonicTimestampWhenTheClockMovesBackward() {
		Instant storedTime = CREATED_AT.plusSeconds(60);
		User active = user(UserStatus.ACTIVE, 0, storedTime);
		User disabled = user(UserStatus.DISABLED, 1, storedTime);
		when(this.tenants.requireActiveForWrite(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(active));
		when(this.timeSource.now()).thenReturn(CREATED_AT);
		when(this.repository.updateStatus(active, disabled)).thenReturn(disabled);

		assertThat(this.operations.disable(TenantId.DEFAULT, USER_ID)).isEqualTo(disabled);
	}

	@Test
	void reportsMissingUsersWithinTheirTenant() {
		when(this.tenants.requireActive(TenantId.DEFAULT)).thenReturn(activeTenant());
		when(this.repository.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> this.operations.requireActive(TenantId.DEFAULT, USER_ID))
			.isInstanceOf(UserNotFoundException.class)
			.extracting("tenantId", "userId")
			.containsExactly(TenantId.DEFAULT, USER_ID);
	}

	private User changeStatus(UserStatus target) {
		return switch (target) {
			case ACTIVE -> this.operations.activate(TenantId.DEFAULT, USER_ID);
			case DISABLED -> this.operations.disable(TenantId.DEFAULT, USER_ID);
			case LOCKED -> this.operations.lock(TenantId.DEFAULT, USER_ID);
			case DELETED -> this.operations.delete(TenantId.DEFAULT, USER_ID);
		};
	}

	private UserStatus sourceFor(UserStatus target) {
		return target == UserStatus.ACTIVE ? UserStatus.DISABLED : UserStatus.ACTIVE;
	}

	private User transition(User user, UserStatus target, Instant changedAt) {
		return switch (target) {
			case ACTIVE -> user.activate(changedAt);
			case DISABLED -> user.disable(changedAt);
			case LOCKED -> user.lock(changedAt);
			case DELETED -> user.delete(changedAt);
		};
	}

	private User user(UserStatus status, long version, Instant updatedAt) {
		return new User(USER_ID, TenantId.DEFAULT, List.of(USERNAME), status, version, CREATED_AT, updatedAt, null);
	}

	private Tenant activeTenant() {
		return new Tenant(TenantId.DEFAULT, "default", "Default", TenantStatus.ACTIVE, 0, CREATED_AT, CREATED_AT);
	}

}
