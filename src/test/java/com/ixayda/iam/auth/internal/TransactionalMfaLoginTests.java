package com.ixayda.iam.auth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.auth.MfaLoginResult;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.RecoveryCodeOperations;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.credential.TotpOperations;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class TransactionalMfaLoginTests {

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e63");

	private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

	private final TotpOperations totp = mock(TotpOperations.class);

	private final RecoveryCodeOperations recoveryCodes = mock(RecoveryCodeOperations.class);

	private final SessionOperations sessions = mock(SessionOperations.class);

	private final LocalPasswordLoginProperties properties =
			new LocalPasswordLoginProperties(Duration.ofHours(8));

	private final TransactionalMfaLogin login =
			new TransactionalMfaLogin(this.totp, this.recoveryCodes, this.sessions, this.properties);

	@Test
	void startsASessionOnlyAfterTotpVerification() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		UserSession session = session();
		try (TotpCodeAttempt code = new TotpCodeAttempt("123456".toCharArray())) {
			when(this.totp.verify(TenantId.DEFAULT, USER_ID, code)).thenReturn(true);
			when(this.sessions.start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
					this.properties.absoluteTtl())).thenReturn(session);

			assertThat(this.login.complete(challenge, code).session()).contains(session);

			InOrder order = inOrder(this.totp, this.sessions);
			order.verify(this.totp).verify(TenantId.DEFAULT, USER_ID, code);
			order.verify(this.sessions).start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
					this.properties.absoluteTtl());
			verifyNoInteractions(this.recoveryCodes);
		}
	}

	@Test
	void startsASessionOnlyAfterConsumingARecoveryCode() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.RECOVERY_CODE));
		UserSession session = session();
		try (RecoveryCodeAttempt code = recoveryCode()) {
			when(this.recoveryCodes.verifyAndConsume(TenantId.DEFAULT, USER_ID, code)).thenReturn(true);
			when(this.sessions.start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
					this.properties.absoluteTtl())).thenReturn(session);

			assertThat(this.login.complete(challenge, code).session()).contains(session);

			InOrder order = inOrder(this.recoveryCodes, this.sessions);
			order.verify(this.recoveryCodes).verifyAndConsume(TenantId.DEFAULT, USER_ID, code);
			order.verify(this.sessions).start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
					this.properties.absoluteTtl());
			verifyNoInteractions(this.totp);
		}
	}

	@Test
	void rejectsInvalidFactorsWithoutStartingASession() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP, MfaFactor.RECOVERY_CODE));
		try (TotpCodeAttempt totpCode = new TotpCodeAttempt("123456".toCharArray());
				RecoveryCodeAttempt recoveryCode = recoveryCode()) {
			when(this.totp.verify(TenantId.DEFAULT, USER_ID, totpCode)).thenReturn(false);
			when(this.recoveryCodes.verifyAndConsume(TenantId.DEFAULT, USER_ID, recoveryCode)).thenReturn(false);

			assertThat(this.login.complete(challenge, totpCode)).isSameAs(MfaLoginResult.rejected());
			assertThat(this.login.complete(challenge, recoveryCode)).isSameAs(MfaLoginResult.rejected());
			verifyNoInteractions(this.sessions);
		}
	}

	@Test
	void rejectsFactorsThatWereNotOfferedWithoutVerifyingThem() {
		MfaChallenge totpOnly = challenge(Set.of(MfaFactor.TOTP));
		MfaChallenge recoveryOnly = challenge(Set.of(MfaFactor.RECOVERY_CODE));
		try (TotpCodeAttempt totpCode = new TotpCodeAttempt("123456".toCharArray());
				RecoveryCodeAttempt recoveryCode = recoveryCode()) {
			assertThat(this.login.complete(recoveryOnly, totpCode)).isSameAs(MfaLoginResult.rejected());
			assertThat(this.login.complete(totpOnly, recoveryCode)).isSameAs(MfaLoginResult.rejected());
			verify(this.totp, never()).verify(TenantId.DEFAULT, USER_ID, totpCode);
			verify(this.recoveryCodes, never()).verifyAndConsume(TenantId.DEFAULT, USER_ID, recoveryCode);
			verifyNoInteractions(this.sessions);
		}
	}

	@Test
	void rejectsNullInputsBeforeTouchingAuthenticationState() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		try (TotpCodeAttempt totpCode = new TotpCodeAttempt("123456".toCharArray())) {
			assertThatThrownBy(() -> this.login.complete(null, totpCode))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.login.complete(challenge, (TotpCodeAttempt) null))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.login.complete(challenge, (RecoveryCodeAttempt) null))
				.isInstanceOf(NullPointerException.class);
			verifyNoInteractions(this.totp, this.recoveryCodes, this.sessions);
		}
	}

	private MfaChallenge challenge(Set<MfaFactor> factors) {
		return new MfaChallenge(MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				TenantId.DEFAULT, USER_ID, NOW, NOW.plusSeconds(300), factors);
	}

	private RecoveryCodeAttempt recoveryCode() {
		return new RecoveryCodeAttempt("012AB-CDEFG-HJKMN-PQRST".toCharArray());
	}

	private UserSession session() {
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e64"), TenantId.DEFAULT,
				USER_ID, SessionAuthenticationMethod.PASSWORD, 0, 0, NOW, NOW.plusSeconds(3600));
	}

}
