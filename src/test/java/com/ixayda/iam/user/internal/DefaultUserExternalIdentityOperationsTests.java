package com.ixayda.iam.user.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
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

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityLinkConflictException;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserExternalIdentity;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class DefaultUserExternalIdentityOperationsTests {

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e82");

	private static final UserId OTHER_USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e83");

	private static final ExternalIdentityProviderId PROVIDER_ID =
			ExternalIdentityProviderId.from("corporate");

	private static final ExternalSubjectId SUBJECT_ID = ExternalSubjectId.from("subject-a");

	private static final ExternalSubjectId OTHER_SUBJECT_ID = ExternalSubjectId.from("subject-b");

	private static final Instant LINKED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final JdbcUserExternalIdentityRepository repository =
			mock(JdbcUserExternalIdentityRepository.class);

	private final UserOperations users = mock(UserOperations.class);

	private final UserTimeSource timeSource = mock(UserTimeSource.class);

	private final DefaultUserExternalIdentityOperations operations =
			new DefaultUserExternalIdentityOperations(this.repository, this.users, this.timeSource);

	@Test
	void linksAfterGuardingTheUserAndCheckingBothUniqueKeys() {
		stubActiveUser();
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.empty());
		when(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID))
			.thenReturn(Optional.empty());
		when(this.timeSource.now()).thenReturn(LINKED_AT);
		when(this.repository.insert(any(UserExternalIdentity.class)))
			.thenAnswer(invocation -> invocation.getArgument(0));

		UserExternalIdentity linked =
				this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID);

		assertThat(linked).isEqualTo(identity(USER_ID, SUBJECT_ID, LINKED_AT));
		InOrder order = inOrder(this.users, this.repository, this.timeSource);
		order.verify(this.users).requireActiveForWrite(TenantId.DEFAULT, USER_ID);
		order.verify(this.repository).findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID);
		order.verify(this.repository).findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID);
		order.verify(this.timeSource).now();
		order.verify(this.repository).insert(linked);
	}

	@Test
	void returnsAnExactExistingMappingIdempotently() {
		UserExternalIdentity existing = identity(USER_ID, SUBJECT_ID, LINKED_AT.minusSeconds(1));
		stubActiveUser();
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.of(existing));

		assertThat(this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID)).isSameAs(existing);
		verify(this.repository, never()).findByUserAndProvider(any(), any(), any());
		verify(this.repository, never()).insert(any());
		verifyNoInteractions(this.timeSource);
	}

	@Test
	void returnsAnExactMappingCommittedBetweenUniqueKeyChecks() {
		UserExternalIdentity existing = identity(USER_ID, SUBJECT_ID, LINKED_AT.minusSeconds(1));
		stubActiveUser();
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.empty());
		when(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID))
			.thenReturn(Optional.of(existing));

		assertThat(this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID)).isSameAs(existing);
		verify(this.repository, never()).insert(any());
		verifyNoInteractions(this.timeSource);
	}

	@Test
	void reportsExistingSubjectAndUserProviderMappingsAsTheSamePublicConflict() {
		stubActiveUser();
		UserExternalIdentity otherOwner = identity(OTHER_USER_ID, SUBJECT_ID, LINKED_AT);
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.of(otherOwner));

		assertGenericConflict(() -> this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID));

		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.empty());
		when(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID))
			.thenReturn(Optional.of(identity(USER_ID, OTHER_SUBJECT_ID, LINKED_AT)));

		assertGenericConflict(() -> this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID));
		verify(this.repository, never()).insert(any());
		verifyNoInteractions(this.timeSource);
	}

	@Test
	void convergesAConcurrentExactLinkAndPreservesTheWinnerTimestamp() {
		UserExternalIdentity winner = identity(USER_ID, SUBJECT_ID, LINKED_AT.minusSeconds(1));
		stubActiveUser();
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.empty())
			.thenReturn(Optional.of(winner));
		when(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID))
			.thenReturn(Optional.empty());
		when(this.timeSource.now()).thenReturn(LINKED_AT);
		when(this.repository.insert(any(UserExternalIdentity.class)))
			.thenThrow(new ExternalSubjectAlreadyLinkedException(TenantId.DEFAULT, PROVIDER_ID));

		assertThat(this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID)).isSameAs(winner);
		verify(this.repository).insert(identity(USER_ID, SUBJECT_ID, LINKED_AT));
	}

	@Test
	void translatesConcurrentOwnershipConflictsWithoutLeakingInternalTypes() {
		stubActiveUser();
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.empty())
			.thenReturn(Optional.of(identity(OTHER_USER_ID, SUBJECT_ID, LINKED_AT)));
		when(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID))
			.thenReturn(Optional.empty());
		when(this.timeSource.now()).thenReturn(LINKED_AT);
		when(this.repository.insert(any(UserExternalIdentity.class)))
			.thenThrow(new ExternalSubjectAlreadyLinkedException(TenantId.DEFAULT, PROVIDER_ID));

		assertGenericConflict(() -> this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID));

		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.empty());
		when(this.repository.insert(any(UserExternalIdentity.class)))
			.thenThrow(new UserProviderAlreadyLinkedException(TenantId.DEFAULT, PROVIDER_ID, USER_ID));

		assertGenericConflict(() -> this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID));
	}

	@Test
	void rejectsAnUnexpectedUserGuardResult() {
		when(this.users.requireActiveForWrite(TenantId.DEFAULT, USER_ID)).thenReturn(user(OTHER_USER_ID));

		assertThatThrownBy(() -> this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, SUBJECT_ID))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("External identity user guard returned a different user");
		verifyNoInteractions(this.repository, this.timeSource);
	}

	@Test
	void delegatesRawLookupsWithoutApplyingLifecycleGuards() {
		UserExternalIdentity identity = identity(USER_ID, SUBJECT_ID, LINKED_AT);
		when(this.repository.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID))
			.thenReturn(Optional.of(identity));
		when(this.repository.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID))
			.thenReturn(Optional.of(identity));

		assertThat(this.operations.findBySubject(TenantId.DEFAULT, PROVIDER_ID, SUBJECT_ID)).contains(identity);
		assertThat(this.operations.findByUserAndProvider(TenantId.DEFAULT, USER_ID, PROVIDER_ID)).contains(identity);
		verifyNoInteractions(this.users, this.timeSource);
	}

	@Test
	void rejectsNullInputBeforeTouchingExternalIdentityState() {
		assertThatThrownBy(() -> this.operations.link(null, USER_ID, PROVIDER_ID, SUBJECT_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.link(TenantId.DEFAULT, null, PROVIDER_ID, SUBJECT_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.link(TenantId.DEFAULT, USER_ID, null, SUBJECT_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.link(TenantId.DEFAULT, USER_ID, PROVIDER_ID, null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.findBySubject(null, PROVIDER_ID, SUBJECT_ID))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> this.operations.findByUserAndProvider(TenantId.DEFAULT, null, PROVIDER_ID))
			.isInstanceOf(NullPointerException.class);
		verifyNoInteractions(this.users, this.repository, this.timeSource);
	}

	private void stubActiveUser() {
		when(this.users.requireActiveForWrite(TenantId.DEFAULT, USER_ID)).thenReturn(user(USER_ID));
	}

	private User user(UserId userId) {
		return new User(userId, TenantId.DEFAULT, List.of(LoginIdentifier.username("alice")), UserStatus.ACTIVE, 0,
				LINKED_AT, LINKED_AT, null);
	}

	private UserExternalIdentity identity(UserId userId, ExternalSubjectId subjectId, Instant linkedAt) {
		return new UserExternalIdentity(TenantId.DEFAULT, PROVIDER_ID, subjectId, userId, linkedAt);
	}

	private void assertGenericConflict(Runnable operation) {
		ExternalIdentityLinkConflictException conflict =
				catchThrowableOfType(ExternalIdentityLinkConflictException.class, operation::run);

		assertThat(conflict).extracting("tenantId", "userId", "providerId")
			.containsExactly(TenantId.DEFAULT, USER_ID, PROVIDER_ID);
		assertThat(conflict)
			.hasMessage("External identity conflicts with an existing mapping for provider corporate in tenant "
					+ TenantId.DEFAULT)
			.hasNoCause();
		assertThat(conflict.getMessage())
			.doesNotContain(SUBJECT_ID.value(), OTHER_SUBJECT_ID.value(), OTHER_USER_ID.toString());
	}

}
