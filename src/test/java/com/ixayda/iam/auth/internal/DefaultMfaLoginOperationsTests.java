package com.ixayda.iam.auth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeConsumeStatus;
import com.ixayda.iam.auth.MfaChallengeOperations;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.auth.MfaLoginResult;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class DefaultMfaLoginOperationsTests {

	private static final LoginAttemptSource SOURCE = LoginAttemptSource.trusted("mfa-login-source");

	private final MfaChallengeOperations challenges = mock(MfaChallengeOperations.class);

	private final TransactionalMfaLogin transactionalLogin = mock(TransactionalMfaLogin.class);

	private final DefaultMfaLoginOperations operations =
			new DefaultMfaLoginOperations(this.challenges, this.transactionalLogin);

	@Test
	void consumesTheChallengeBeforeCompletingTotp() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		try (TotpCodeAttempt code = new TotpCodeAttempt("123456".toCharArray())) {
			when(this.challenges.consume(challenge, SOURCE)).thenReturn(MfaChallengeConsumeStatus.CONSUMED);
			when(this.transactionalLogin.complete(challenge, code)).thenReturn(MfaLoginResult.rejected());

			assertThat(this.operations.complete(challenge, SOURCE, code)).isSameAs(MfaLoginResult.rejected());

			InOrder order = inOrder(this.challenges, this.transactionalLogin);
			order.verify(this.challenges).consume(challenge, SOURCE);
			order.verify(this.transactionalLogin).complete(challenge, code);
		}
	}

	@Test
	void consumesTheChallengeBeforeCompletingARecoveryCode() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.RECOVERY_CODE));
		try (RecoveryCodeAttempt code = recoveryCode()) {
			when(this.challenges.consume(challenge, SOURCE)).thenReturn(MfaChallengeConsumeStatus.CONSUMED);
			when(this.transactionalLogin.complete(challenge, code)).thenReturn(MfaLoginResult.rejected());

			assertThat(this.operations.complete(challenge, SOURCE, code)).isSameAs(MfaLoginResult.rejected());

			InOrder order = inOrder(this.challenges, this.transactionalLogin);
			order.verify(this.challenges).consume(challenge, SOURCE);
			order.verify(this.transactionalLogin).complete(challenge, code);
		}
	}

	@Test
	void rejectsConsumedChallengesThatDoNotOfferTheSelectedFactor() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.RECOVERY_CODE));
		try (TotpCodeAttempt code = new TotpCodeAttempt("123456".toCharArray())) {
			when(this.challenges.consume(challenge, SOURCE)).thenReturn(MfaChallengeConsumeStatus.CONSUMED);

			assertThat(this.operations.complete(challenge, SOURCE, code)).isSameAs(MfaLoginResult.rejected());
			verifyNoInteractions(this.transactionalLogin);
		}
	}

	@Test
	void mapsRejectedAndUnavailableChallengeConsumptionWithoutStartingATransaction() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		try (TotpCodeAttempt rejected = new TotpCodeAttempt("123456".toCharArray());
				TotpCodeAttempt unavailable = new TotpCodeAttempt("654321".toCharArray())) {
			when(this.challenges.consume(challenge, SOURCE))
				.thenReturn(MfaChallengeConsumeStatus.REJECTED, MfaChallengeConsumeStatus.UNAVAILABLE);

			assertThat(this.operations.complete(challenge, SOURCE, rejected)).isSameAs(MfaLoginResult.rejected());
			assertThat(this.operations.complete(challenge, SOURCE, unavailable)).isSameAs(MfaLoginResult.unavailable());
			verifyNoInteractions(this.transactionalLogin);
		}
	}

	@Test
	void rejectsNullInputsBeforeConsumingAChallenge() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		try (TotpCodeAttempt totp = new TotpCodeAttempt("123456".toCharArray());
				RecoveryCodeAttempt recovery = recoveryCode()) {
			assertThatThrownBy(() -> this.operations.complete(null, SOURCE, totp))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.operations.complete(challenge, null, totp))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.operations.complete(challenge, SOURCE, (TotpCodeAttempt) null))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.operations.complete(challenge, SOURCE, (RecoveryCodeAttempt) null))
				.isInstanceOf(NullPointerException.class);
			verifyNoInteractions(this.challenges, this.transactionalLogin);
		}
	}

	@Test
	void refusesAnExistingDatabaseTransactionBeforeConsumingAChallenge() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		try (TotpCodeAttempt code = new TotpCodeAttempt("123456".toCharArray())) {
			TransactionSynchronizationManager.setActualTransactionActive(true);
			try {
				assertThatThrownBy(() -> this.operations.complete(challenge, SOURCE, code))
					.isInstanceOf(IllegalTransactionStateException.class);
			}
			finally {
				TransactionSynchronizationManager.setActualTransactionActive(false);
			}
			verifyNoInteractions(this.challenges, this.transactionalLogin);
		}
	}

	private MfaChallenge challenge(Set<MfaFactor> factors) {
		Instant now = Instant.parse("2026-01-01T00:00:00Z");
		return new MfaChallenge(MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				TenantId.DEFAULT, UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e63"), now,
				now.plusSeconds(300), factors);
	}

	private RecoveryCodeAttempt recoveryCode() {
		return new RecoveryCodeAttempt("012AB-CDEFG-HJKMN-PQRST".toCharArray());
	}

}
