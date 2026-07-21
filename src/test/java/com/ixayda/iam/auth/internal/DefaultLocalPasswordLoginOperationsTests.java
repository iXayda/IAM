package com.ixayda.iam.auth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.auth.LocalPasswordLoginResult;
import com.ixayda.iam.auth.LocalPasswordLoginStatus;
import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeIssue;
import com.ixayda.iam.auth.MfaChallengeOperations;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptDecision;
import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptLease;
import com.ixayda.iam.ratelimit.LoginAttemptLimiter;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class DefaultLocalPasswordLoginOperationsTests {

	private static final LoginKey LOGIN_KEY = LoginKey.from("alice");

	private static final LoginAttemptSource SOURCE = LoginAttemptSource.trusted("203.0.113.8");

	private static final LoginAttemptKey ATTEMPT_KEY = new LoginAttemptKey(TenantId.DEFAULT, LOGIN_KEY, SOURCE);

	private static final LoginAttemptLease LEASE =
			LoginAttemptLease.from("0123456789abcdefghijkl");

	private final LoginAttemptLimiter limiter = mock(LoginAttemptLimiter.class);

	private final TransactionalLocalPasswordLogin transactionalLogin = mock(TransactionalLocalPasswordLogin.class);

	private final MfaChallengeOperations challenges = mock(MfaChallengeOperations.class);

	private final AuthenticationAuditRecorder audit = mock(AuthenticationAuditRecorder.class);

	private final DefaultLocalPasswordLoginOperations operations =
			new DefaultLocalPasswordLoginOperations(this.limiter, this.transactionalLogin, this.challenges, this.audit);

	@Test
	void recordsSuccessOnlyAfterAuthenticationReturns() {
		UserSession session = session();
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.allowed(LEASE));
			when(this.transactionalLogin.authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
				.thenReturn(PasswordLoginTransactionResult.authenticated(session));

			LocalPasswordLoginResult result =
					this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);

			assertThat(result.session()).contains(session);
			InOrder order = inOrder(this.limiter, this.transactionalLogin);
			order.verify(this.limiter).acquire(ATTEMPT_KEY);
			order.verify(this.transactionalLogin).authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);
			order.verify(this.limiter).recordSuccess(ATTEMPT_KEY, LEASE);
		}
	}

	@Test
	void preservesTheAttemptAfterRejectedAuthentication() {
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.allowed(LEASE));
			when(this.transactionalLogin.authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
				.thenReturn(PasswordLoginTransactionResult.rejected());

			LocalPasswordLoginResult result =
					this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);

			assertThat(result).isSameAs(LocalPasswordLoginResult.rejected());
			verify(this.limiter, never()).recordSuccess(ATTEMPT_KEY, LEASE);
		}
	}

	@Test
	void returnsThrottledWithoutAuthenticating() {
		Duration retryAfter = Duration.ofSeconds(9);
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.throttled(retryAfter));

			LocalPasswordLoginResult result =
					this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);

			assertThat(result.status()).isEqualTo(LocalPasswordLoginStatus.THROTTLED);
			assertThat(result.retryAfter()).contains(retryAfter);
			verifyNoInteractions(this.transactionalLogin);
			verifyNoInteractions(this.challenges);
			verify(this.limiter, never()).recordSuccess(any(), any());
			verify(this.audit).loginThrottled(TenantId.DEFAULT, SOURCE, retryAfter);
		}
	}

	@Test
	void returnsUnavailableWithoutAuthenticating() {
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.unavailable());

			LocalPasswordLoginResult result =
					this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);

			assertThat(result).isSameAs(LocalPasswordLoginResult.unavailable());
			verifyNoInteractions(this.transactionalLogin);
			verifyNoInteractions(this.challenges);
			verify(this.limiter, never()).recordSuccess(any(), any());
			verify(this.audit).loginUnavailable(TenantId.DEFAULT, SOURCE, "rate_limit");
		}
	}

	@Test
	void doesNotRecordSuccessWhenAuthenticationFailsUnexpectedly() {
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.allowed(LEASE));
			when(this.transactionalLogin.authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
				.thenThrow(new IllegalStateException("authentication transaction failed"));

			assertThatThrownBy(() -> this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("authentication transaction failed");
			verify(this.limiter, never()).recordSuccess(ATTEMPT_KEY, LEASE);
		}
	}

	@Test
	void returnsTheCommittedSuccessWhenAcknowledgementFailsUnexpectedly() {
		UserSession session = session();
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.allowed(LEASE));
			when(this.transactionalLogin.authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
				.thenReturn(PasswordLoginTransactionResult.authenticated(session));
			doThrow(new IllegalStateException("unexpected reset failure"))
				.when(this.limiter)
				.recordSuccess(ATTEMPT_KEY, LEASE);

			LocalPasswordLoginResult result =
					this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);

			assertThat(result.session()).contains(session);
			verify(this.limiter).recordSuccess(ATTEMPT_KEY, LEASE);
		}
	}

	@Test
	void issuesAChallengeAndRecordsPasswordSuccessWithoutCreatingASession() {
		MfaChallenge challenge = challenge();
		PasswordLoginTransactionResult verified = PasswordLoginTransactionResult.mfaRequired(
				challenge.userId(), challenge.passwordVerifiedAt(), challenge.factors());
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.allowed(LEASE));
			when(this.transactionalLogin.authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt)).thenReturn(verified);
			when(this.challenges.issue(TenantId.DEFAULT, challenge.userId(), SOURCE,
					challenge.passwordVerifiedAt(), challenge.factors()))
				.thenReturn(MfaChallengeIssue.issued(challenge));

			LocalPasswordLoginResult result =
					this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt);

			assertThat(result.mfaRequired()).isTrue();
			assertThat(result.challenge()).contains(challenge);
			verify(this.limiter).recordSuccess(ATTEMPT_KEY, LEASE);
		}
	}

	@Test
	void failsClosedWhenAChallengeCannotBeIssued() {
		MfaChallenge challenge = challenge();
		PasswordLoginTransactionResult verified = PasswordLoginTransactionResult.mfaRequired(
				challenge.userId(), challenge.passwordVerifiedAt(), challenge.factors());
		try (PasswordAttempt attempt = attempt()) {
			when(this.limiter.acquire(ATTEMPT_KEY)).thenReturn(LoginAttemptDecision.allowed(LEASE));
			when(this.transactionalLogin.authenticate(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt)).thenReturn(verified);
			when(this.challenges.issue(any(), any(), any(), any(), any()))
				.thenReturn(MfaChallengeIssue.unavailable());

			assertThat(this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
				.isSameAs(LocalPasswordLoginResult.unavailable());
			verify(this.limiter, never()).recordSuccess(ATTEMPT_KEY, LEASE);
			verify(this.audit).loginUnavailable(TenantId.DEFAULT, SOURCE, "mfa_challenge");
		}
	}

	@Test
	void rejectsNullInputBeforeAcquiringAnAttempt() {
		try (PasswordAttempt attempt = attempt()) {
			assertThatThrownBy(() -> this.operations.login(null, LOGIN_KEY, SOURCE, attempt))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.operations.login(TenantId.DEFAULT, null, SOURCE, attempt))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.operations.login(TenantId.DEFAULT, LOGIN_KEY, null, attempt))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, null))
				.isInstanceOf(NullPointerException.class);
			verifyNoInteractions(this.limiter, this.transactionalLogin, this.challenges, this.audit);
		}
	}

	@Test
	void rejectsAnExistingDatabaseTransactionBeforeAcquiringAnAttempt() {
		try (PasswordAttempt attempt = attempt()) {
			TransactionSynchronizationManager.setActualTransactionActive(true);
			try {
				assertThatThrownBy(() -> this.operations.login(TenantId.DEFAULT, LOGIN_KEY, SOURCE, attempt))
					.isInstanceOf(IllegalTransactionStateException.class)
					.hasMessage("Local password login must not run inside a database transaction");
			}
			finally {
				TransactionSynchronizationManager.setActualTransactionActive(false);
			}
			verifyNoInteractions(this.limiter, this.transactionalLogin, this.challenges, this.audit);
		}
	}

	private PasswordAttempt attempt() {
		return new PasswordAttempt("candidate-password".toCharArray());
	}

	private UserSession session() {
		Instant now = Instant.parse("2026-01-01T00:00:00Z");
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62"), SessionAuthenticationMethod.PASSWORD,
				0, 0, now, now.plus(Duration.ofHours(8)));
	}

	private MfaChallenge challenge() {
		Instant now = Instant.parse("2026-01-01T00:00:00Z");
		return new MfaChallenge(MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				TenantId.DEFAULT, UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e63"), now,
				now.plusSeconds(300), Set.of(MfaFactor.TOTP));
	}

}
