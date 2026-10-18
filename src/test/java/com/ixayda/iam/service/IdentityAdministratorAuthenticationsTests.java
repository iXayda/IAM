package com.ixayda.iam.service;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpVerification;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.repository.IdentityBrowserSessionRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class IdentityAdministratorAuthenticationsTests {

	private static final long ORIGINAL_EXPIRY = 1_000L;
	private static final long RENEWED_EXPIRY = 2_000L;
	private final UUID userId = UUID.randomUUID();
	private final long authenticatedAt = System.currentTimeMillis() - 1_000L;
	private final IdentityUsers users = mock(IdentityUsers.class);
	private final IdentityBrowserSessionRepository repository = mock(IdentityBrowserSessionRepository.class);
	private final IdentityAdministratorSessions administrators = mock(IdentityAdministratorSessions.class);
	private final IdentityTotps totps = mock(IdentityTotps.class);
	private final TotpAuthenticationLimits limits = mock(TotpAuthenticationLimits.class);
	private final SecurityAudits audits = mock(SecurityAudits.class);
	private final PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
	@SuppressWarnings("unchecked")
	private final Function<IdentityAdministratorAuthentication, String> persist = mock(Function.class);
	private final AtomicLong databaseTime = new AtomicLong(ORIGINAL_EXPIRY - 1);
	private final AtomicLong storedExpiry = new AtomicLong(ORIGINAL_EXPIRY);
	private final TotpAuthenticationContext context = new TotpAuthenticationContext(
			"internal:administrator-test", InetAddress.getLoopbackAddress(), UUID.randomUUID());
	private final IdentityTotpVerification verification = new IdentityTotpVerification(
			this.userId, UUID.randomUUID(), 1L, 1L, Instant.now(), this.context.correlationId());
	private final IdentityAdministratorAuthentication evidence = new IdentityAdministratorAuthentication(
			this.userId, this.verification.factorId(), 1L, this.authenticatedAt, this.verification.verifiedAt());
	private IdentityAdministratorAuthentications authentications;

	@BeforeEach
	void configureCurrentPasswordSession() {
		when(this.manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
		when(this.limits.lock(this.userId, this.context)).thenReturn(new TotpAuthenticationLimits.Attempt("source", "account", true));
		when(this.users.lockById(this.userId)).thenReturn(
				new IdentityUser(this.userId, "alice", "Alice", IdentityUser.Status.ACTIVE, Instant.EPOCH));
		when(this.users.hasCurrentPasswordVersion(this.userId, 1L)).thenReturn(true);
		when(this.repository.lock("original-session")).thenReturn(true);
		when(this.repository.ownedSessionExpiry("original-session", this.userId)).thenAnswer(invocation ->
				this.storedExpiry.get() > this.databaseTime.get() ? Optional.of(this.storedExpiry.get()) : Optional.empty());
		when(this.repository.isBeforeExpiry(anyLong())).thenAnswer(invocation ->
				invocation.<Long>getArgument(0) > this.databaseTime.get());
		when(this.administrators.isAdministrator(this.userId)).thenReturn(true);
		when(this.totps.verifyInTransaction(this.userId, "123456", this.context)).thenReturn(Optional.of(this.verification));
		when(this.persist.apply(this.evidence)).thenAnswer(invocation -> {
			this.storedExpiry.set(RENEWED_EXPIRY);
			return "rotated-session";
		});
		var sessions = new IdentityBrowserSessions(this.users, this.repository, this.audits, this.administrators, this.manager, 1800, 28800);
		this.authentications = new IdentityAdministratorAuthentications(this.users, sessions, this.administrators,
				this.totps, this.limits, this.audits, this.manager);
	}

	@Test
	void commitsElevationOnlyWhileTheOriginalSessionDeadlineIsCurrent() {
		assertThat(authenticate(this.authenticatedAt)).isEqualTo(IdentityAdministratorAuthentications.Result.AUTHENTICATED);
		assertSuccessfulStepsBeforeCompletion(true);
		verify(this.manager, never()).rollback(any());
	}

	@ParameterizedTest
	@EnumSource(DeadlineCrossing.class)
	void crossingTheOriginalIdleDeadlineRollsBackTheFactorSessionAndAudit(DeadlineCrossing crossing) {
		when(this.totps.verifyInTransaction(this.userId, "123456", this.context)).thenAnswer(invocation -> {
			if (crossing == DeadlineCrossing.TOTP_VERIFICATION) { this.databaseTime.set(ORIGINAL_EXPIRY); }
			return Optional.of(this.verification);
		});
		doAnswer(invocation -> {
			if (crossing == DeadlineCrossing.SESSION_PERSISTENCE) { this.databaseTime.set(ORIGINAL_EXPIRY); }
			// Persistence may renew storage, but cannot replace the workflow's original authorization deadline.
			this.storedExpiry.set(RENEWED_EXPIRY);
			return "rotated-session";
		}).when(this.persist).apply(this.evidence);
		doAnswer(invocation -> {
			if (crossing == DeadlineCrossing.SUCCESS_AUDIT) { this.databaseTime.set(ORIGINAL_EXPIRY); }
			return null;
		}).when(this.audits).recordSuccess(eq(Action.ADMIN_MFA_AUTHENTICATED), eq(this.userId), any());
		assertThat(this.storedExpiry.get()).isEqualTo(ORIGINAL_EXPIRY);
		assertThat(this.databaseTime.get()).isLessThan(ORIGINAL_EXPIRY);
		assertThatIllegalStateException().isThrownBy(() -> authenticate(this.authenticatedAt))
				.withMessage("Administrator authentication is no longer current");
		assertThat(this.storedExpiry.get()).isEqualTo(RENEWED_EXPIRY).isGreaterThan(this.databaseTime.get());
		assertSuccessfulStepsBeforeCompletion(false);
		verify(this.manager, never()).commit(any());
	}

	@ParameterizedTest
	@EnumSource(InvalidSession.class)
	void rejectsUnavailableOrExpiredSessionsBeforeConsumingTotpOrPersisting(InvalidSession state) {
		long passwordTime = this.authenticatedAt;
		if (state == InvalidSession.MISSING) { when(this.repository.lock("original-session")).thenReturn(false); }
		if (state == InvalidSession.IDLE_EXPIRED) { this.databaseTime.set(ORIGINAL_EXPIRY); }
		if (state == InvalidSession.ABSOLUTE_EXPIRED) { passwordTime -= 28_800_000L; }
		assertThat(authenticate(passwordTime)).isEqualTo(IdentityAdministratorAuthentications.Result.INVALID_SESSION);
		verifyNoInteractions(this.totps, this.persist, this.administrators, this.audits);
		verify(this.repository, never()).isBeforeExpiry(anyLong());
		verify(this.manager).commit(any());
		verify(this.manager, never()).rollback(any());
	}

	private IdentityAdministratorAuthentications.Result authenticate(long passwordTime) {
		return this.authentications.authenticate(this.userId, "original-session", 1L, passwordTime,
				"123456", this.context, this.persist);
	}

	private void assertSuccessfulStepsBeforeCompletion(boolean committed) {
		var order = inOrder(this.manager, this.limits, this.users, this.repository, this.administrators, this.totps, this.persist, this.audits);
		order.verify(this.manager).getTransaction(any());
		order.verify(this.limits).lock(this.userId, this.context);
		order.verify(this.users).lockById(this.userId);
		order.verify(this.repository).lock("original-session");
		order.verify(this.repository).ownedSessionExpiry("original-session", this.userId);
		order.verify(this.users).hasCurrentPasswordVersion(this.userId, 1L);
		order.verify(this.administrators).isAdministrator(this.userId);
		order.verify(this.totps).verifyInTransaction(this.userId, "123456", this.context);
		order.verify(this.persist).apply(this.evidence);
		order.verify(this.administrators).requireStored("original-session", "rotated-session", this.evidence);
		order.verify(this.audits).recordSuccess(eq(Action.ADMIN_MFA_AUTHENTICATED), eq(this.userId), any());
		order.verify(this.repository).isBeforeExpiry(ORIGINAL_EXPIRY);
		if (committed) { order.verify(this.manager).commit(any()); }
		else { order.verify(this.manager).rollback(any()); }
		order.verifyNoMoreInteractions();
	}

	private enum DeadlineCrossing { TOTP_VERIFICATION, SESSION_PERSISTENCE, SUCCESS_AUDIT }
	private enum InvalidSession { MISSING, IDLE_EXPIRED, ABSOLUTE_EXPIRED }
}
