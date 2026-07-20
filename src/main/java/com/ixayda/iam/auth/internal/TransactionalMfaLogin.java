package com.ixayda.iam.auth.internal;

import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.auth.MfaLoginResult;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.RecoveryCodeOperations;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.credential.TotpOperations;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class TransactionalMfaLogin {

	private final TotpOperations totp;

	private final RecoveryCodeOperations recoveryCodes;

	private final SessionOperations sessions;

	private final LocalPasswordLoginProperties properties;

	private final AuthenticationTimeSource timeSource;

	TransactionalMfaLogin(TotpOperations totp, RecoveryCodeOperations recoveryCodes, SessionOperations sessions,
			LocalPasswordLoginProperties properties, AuthenticationTimeSource timeSource) {
		this.totp = totp;
		this.recoveryCodes = recoveryCodes;
		this.sessions = sessions;
		this.properties = properties;
		this.timeSource = timeSource;
	}

	@Transactional
	public MfaLoginResult complete(MfaChallenge challenge, TotpCodeAttempt code) {
		Objects.requireNonNull(challenge, "MFA challenge must not be null");
		Objects.requireNonNull(code, "TOTP code attempt must not be null");
		if (!challenge.supports(MfaFactor.TOTP)
				|| !this.totp.verify(challenge.tenantId(), challenge.userId(), code)) {
			return MfaLoginResult.rejected();
		}
		return authenticated(challenge, SessionAuthenticationFactorType.TOTP);
	}

	@Transactional
	public MfaLoginResult complete(MfaChallenge challenge, RecoveryCodeAttempt code) {
		Objects.requireNonNull(challenge, "MFA challenge must not be null");
		Objects.requireNonNull(code, "Recovery code attempt must not be null");
		if (!challenge.supports(MfaFactor.RECOVERY_CODE)
				|| !this.recoveryCodes.verifyAndConsume(challenge.tenantId(), challenge.userId(), code)) {
			return MfaLoginResult.rejected();
		}
		return authenticated(challenge, SessionAuthenticationFactorType.RECOVERY_CODE);
	}

	private MfaLoginResult authenticated(MfaChallenge challenge, SessionAuthenticationFactorType completedFactor) {
		Set<SessionAuthenticationFactor> factors = Set.of(
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD,
						challenge.passwordVerifiedAt()),
				new SessionAuthenticationFactor(completedFactor, this.timeSource.now()));
		return MfaLoginResult.authenticated(this.sessions.start(challenge.tenantId(), challenge.userId(),
				SessionAuthenticationMethod.PASSWORD, factors, this.properties.absoluteTtl()));
	}

}
