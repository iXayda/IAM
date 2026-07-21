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
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class TransactionalMfaLogin {

	private final TotpOperations totp;

	private final RecoveryCodeOperations recoveryCodes;

	private final SessionOperations sessions;

	private final LocalPasswordLoginProperties properties;

	private final AuthenticationTimeSource timeSource;

	private final AuthenticationAuditRecorder audit;

	TransactionalMfaLogin(TotpOperations totp, RecoveryCodeOperations recoveryCodes, SessionOperations sessions,
			LocalPasswordLoginProperties properties, AuthenticationTimeSource timeSource,
			AuthenticationAuditRecorder audit) {
		this.totp = totp;
		this.recoveryCodes = recoveryCodes;
		this.sessions = sessions;
		this.properties = properties;
		this.timeSource = timeSource;
		this.audit = audit;
	}

	@Transactional
	public MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, TotpCodeAttempt code) {
		Objects.requireNonNull(challenge, "MFA challenge must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		Objects.requireNonNull(code, "TOTP code attempt must not be null");
		if (!challenge.supports(MfaFactor.TOTP)
				|| !this.totp.verify(challenge.tenantId(), challenge.userId(), code)) {
			this.audit.mfaFailed(challenge, source, MfaFactor.TOTP, "invalid_code");
			return MfaLoginResult.rejected();
		}
		return authenticated(challenge, source, SessionAuthenticationFactorType.TOTP);
	}

	@Transactional
	public MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, RecoveryCodeAttempt code) {
		Objects.requireNonNull(challenge, "MFA challenge must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		Objects.requireNonNull(code, "Recovery code attempt must not be null");
		if (!challenge.supports(MfaFactor.RECOVERY_CODE)
				|| !this.recoveryCodes.verifyAndConsume(challenge.tenantId(), challenge.userId(), code)) {
			this.audit.mfaFailed(challenge, source, MfaFactor.RECOVERY_CODE, "invalid_code");
			return MfaLoginResult.rejected();
		}
		return authenticated(challenge, source, SessionAuthenticationFactorType.RECOVERY_CODE);
	}

	private MfaLoginResult authenticated(MfaChallenge challenge, LoginAttemptSource source,
			SessionAuthenticationFactorType completedFactor) {
		Set<SessionAuthenticationFactor> factors = Set.of(
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD,
						challenge.passwordVerifiedAt()),
				new SessionAuthenticationFactor(completedFactor, this.timeSource.now()));
		UserSession session = this.sessions.start(challenge.tenantId(), challenge.userId(),
				SessionAuthenticationMethod.PASSWORD, factors, this.properties.absoluteTtl());
		this.audit.loginSucceeded(session, source, completedFactor);
		return MfaLoginResult.authenticated(session);
	}

}
