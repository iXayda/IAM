package com.ixayda.iam.session.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.ixayda.iam.session.SessionAbsoluteTtl;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionStatus;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.session.UserSessionNotFoundException;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.tenant.TenantStatus;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class DefaultSessionOperationsTests {

	private static final TenantId TENANT_ID = TenantId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e51");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e52");

	private static final SessionId SESSION_ID =
			SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e53");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final Instant NOW = CREATED_AT.plusSeconds(60);

	private static final SessionAbsoluteTtl TTL = new SessionAbsoluteTtl(Duration.ofHours(8));

	private final JdbcUserSessionRepository repository = mock(JdbcUserSessionRepository.class);

	private final TenantOperations tenants = mock(TenantOperations.class);

	private final UserOperations users = mock(UserOperations.class);

	private final SessionTimeSource timeSource = mock(SessionTimeSource.class);

	private final DefaultSessionOperations operations =
			new DefaultSessionOperations(this.repository, this.tenants, this.users, this.timeSource);

	@BeforeEach
	void startTransactionContext() {
		TransactionSynchronizationManager.setActualTransactionActive(true);
		TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
	}

	@AfterEach
	void clearTransactionContext() {
		TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
		TransactionSynchronizationManager.setActualTransactionActive(false);
	}

	@Test
	void startsASessionAfterLockingAndCapturingLifecycleVersions() {
		Tenant tenant = tenant(TenantStatus.ACTIVE, 4);
		User user = user(UserStatus.ACTIVE, 7);
		when(this.tenants.requireActiveForWrite(TENANT_ID)).thenReturn(tenant);
		when(this.users.requireActiveForWrite(TENANT_ID, USER_ID)).thenReturn(user);
		when(this.timeSource.now()).thenReturn(NOW);
		when(this.repository.insert(any())).thenAnswer(invocation -> invocation.getArgument(0));

		UserSession session =
				this.operations.start(TENANT_ID, USER_ID, SessionAuthenticationMethod.PASSWORD, TTL);

		assertThat(session.id()).isNotNull();
		assertThat(session.tenantId()).isEqualTo(TENANT_ID);
		assertThat(session.userId()).isEqualTo(USER_ID);
		assertThat(session.authenticationMethod()).isEqualTo(SessionAuthenticationMethod.PASSWORD);
		assertThat(session.status()).isEqualTo(SessionStatus.ACTIVE);
		assertThat(session.issuedTenantVersion()).isEqualTo(4);
		assertThat(session.issuedUserVersion()).isEqualTo(7);
		assertThat(session.authenticatedAt()).isEqualTo(NOW);
		assertThat(session.expiresAt()).isEqualTo(NOW.plus(TTL.value()));

		InOrder order = inOrder(this.tenants, this.users, this.timeSource, this.repository);
		order.verify(this.tenants).requireActiveForWrite(TENANT_ID);
		order.verify(this.users).requireActiveForWrite(TENANT_ID, USER_ID);
		order.verify(this.timeSource).now();
		ArgumentCaptor<UserSession> inserted = ArgumentCaptor.forClass(UserSession.class);
		order.verify(this.repository).insert(inserted.capture());
		assertThat(inserted.getValue()).isEqualTo(session);
	}

	@Test
	void rejectsStartingOutsideAnExistingReadWriteTransaction() {
		TransactionSynchronizationManager.setActualTransactionActive(false);

		assertThatThrownBy(() -> this.operations.start(TENANT_ID, USER_ID,
				SessionAuthenticationMethod.PASSWORD, TTL))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Starting a session requires an existing read-write transaction");

		TransactionSynchronizationManager.setActualTransactionActive(true);
		TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);
		assertThatThrownBy(() -> this.operations.start(TENANT_ID, USER_ID,
				SessionAuthenticationMethod.PASSWORD, TTL))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Starting a session requires an existing read-write transaction");
		verifyNoInteractions(this.tenants, this.users, this.timeSource, this.repository);
	}

	@Test
	void findsRawSessionMetadataWithinTheTenant() {
		UserSession session = activeSession();
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(session));

		assertThat(this.operations.findById(TENANT_ID, SESSION_ID)).contains(session);
	}

	@Test
	void returnsASessionWhenAllUsabilityFactsMatch() {
		UserSession session = activeSession();
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(session));
		when(this.timeSource.now()).thenReturn(NOW);
		when(this.tenants.findById(TENANT_ID)).thenReturn(Optional.of(tenant(TenantStatus.ACTIVE, 4)));
		when(this.users.findById(TENANT_ID, USER_ID)).thenReturn(Optional.of(user(UserStatus.ACTIVE, 7)));

		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).contains(session);
	}

	@Test
	void rejectsMissingRevokedAndExpiredSessionsBeforeLifecycleLookup() {
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.empty());
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();

		UserSession revoked = activeSession().revoke(NOW);
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(revoked));
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();

		UserSession expired = session(NOW);
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(expired));
		when(this.timeSource.now()).thenReturn(NOW);
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();

		verifyNoInteractions(this.tenants, this.users);
	}

	@Test
	void rejectsMissingInactiveOrVersionChangedTenants() {
		UserSession session = activeSession();
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(session));
		when(this.timeSource.now()).thenReturn(NOW);
		when(this.tenants.findById(TENANT_ID))
			.thenReturn(Optional.empty())
			.thenReturn(Optional.of(tenant(TenantStatus.DISABLED, 4)))
			.thenReturn(Optional.of(tenant(TenantStatus.ACTIVE, 5)));

		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();
		verifyNoInteractions(this.users);
	}

	@Test
	void rejectsMissingInactiveOrVersionChangedUsers() {
		UserSession session = activeSession();
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(session));
		when(this.timeSource.now()).thenReturn(NOW);
		when(this.tenants.findById(TENANT_ID)).thenReturn(Optional.of(tenant(TenantStatus.ACTIVE, 4)));
		when(this.users.findById(TENANT_ID, USER_ID))
			.thenReturn(Optional.empty())
			.thenReturn(Optional.of(user(UserStatus.DISABLED, 7)))
			.thenReturn(Optional.of(user(UserStatus.ACTIVE, 8)));

		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();
		assertThat(this.operations.findUsable(TENANT_ID, SESSION_ID)).isEmpty();
	}

	@Test
	void revokesAnActiveSessionAndKeepsRevocationIdempotent() {
		UserSession current = activeSession();
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(NOW);
		when(this.repository.update(any(), any())).thenAnswer(invocation -> invocation.getArgument(1));

		UserSession revoked = this.operations.revoke(TENANT_ID, SESSION_ID);

		assertThat(revoked.isRevoked()).isTrue();
		assertThat(revoked.revokedAt()).isEqualTo(NOW);
		verify(this.repository).update(current, revoked);

		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.of(revoked));
		assertThat(this.operations.revoke(TENANT_ID, SESSION_ID)).isSameAs(revoked);
		verify(this.repository).update(any(), any());
	}

	@Test
	void convergesOnAConcurrentRevocation() {
		UserSession current = activeSession();
		UserSession latest = current.revoke(NOW);
		when(this.repository.findById(TENANT_ID, SESSION_ID))
			.thenReturn(Optional.of(current))
			.thenReturn(Optional.of(latest));
		when(this.timeSource.now()).thenReturn(NOW);
		when(this.repository.update(any(), any()))
			.thenThrow(new UserSessionConcurrentUpdateException(TENANT_ID, SESSION_ID, 0));

		assertThat(this.operations.revoke(TENANT_ID, SESSION_ID)).isSameAs(latest);
	}

	@Test
	void reportsMissingSessionsWithoutLeakingAnotherTenant() {
		when(this.repository.findById(TENANT_ID, SESSION_ID)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> this.operations.revoke(TENANT_ID, SESSION_ID))
			.isInstanceOf(UserSessionNotFoundException.class)
			.extracting("tenantId", "sessionId")
			.containsExactly(TENANT_ID, SESSION_ID);
		verify(this.repository, never()).update(any(), any());
	}

	private UserSession activeSession() {
		return session(NOW.plusSeconds(60));
	}

	private UserSession session(Instant expiresAt) {
		return UserSession.start(SESSION_ID, TENANT_ID, USER_ID, SessionAuthenticationMethod.PASSWORD, 4, 7,
				CREATED_AT, expiresAt);
	}

	private Tenant tenant(TenantStatus status, long version) {
		return new Tenant(TENANT_ID, "session-tests", "Session Tests", status, version, CREATED_AT, CREATED_AT);
	}

	private User user(UserStatus status, long version) {
		return new User(USER_ID, TENANT_ID, List.of(LoginIdentifier.username("session-user")), status, version,
				CREATED_AT, CREATED_AT, null);
	}

}
