package com.ixayda.iam.auth.internal;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.credential.RecoveryCodeOperations;
import com.ixayda.iam.credential.TotpOperations;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class TransactionalLocalPasswordLogin {

	private final UserOperations users;

	private final PasswordOperations passwords;

	private final TotpOperations totp;

	private final RecoveryCodeOperations recoveryCodes;

	private final SessionOperations sessions;

	private final LocalPasswordLoginProperties properties;

	private final AuthenticationTimeSource timeSource;

	private final AuthenticationAuditRecorder audit;

	TransactionalLocalPasswordLogin(UserOperations users, PasswordOperations passwords, TotpOperations totp,
			RecoveryCodeOperations recoveryCodes, SessionOperations sessions, LocalPasswordLoginProperties properties,
			AuthenticationTimeSource timeSource, AuthenticationAuditRecorder audit) {
		this.users = users;
		this.passwords = passwords;
		this.totp = totp;
		this.recoveryCodes = recoveryCodes;
		this.sessions = sessions;
		this.properties = properties;
		this.timeSource = timeSource;
		this.audit = audit;
	}

	@Transactional
	public PasswordLoginTransactionResult authenticate(TenantId tenantId, LoginKey loginKey, LoginAttemptSource source,
			PasswordAttempt password) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(loginKey, "Login key must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		Objects.requireNonNull(password, "Password attempt must not be null");

		Optional<User> candidate = this.users.findByLogin(tenantId, loginKey);
		User user = candidate.orElse(null);
		if (user == null || !user.isActive()) {
			this.passwords.performDummyVerification(password);
			this.audit.passwordFailed(tenantId, user == null ? null : user.id(), source);
			return PasswordLoginTransactionResult.rejected();
		}

		if (!this.passwords.verifyPassword(tenantId, user.id(), password)) {
			this.audit.passwordFailed(tenantId, user.id(), source);
			return PasswordLoginTransactionResult.rejected();
		}

		EnumSet<MfaFactor> factors = EnumSet.noneOf(MfaFactor.class);
		if (this.totp.hasActiveCredential(tenantId, user.id())) {
			factors.add(MfaFactor.TOTP);
		}
		if (this.recoveryCodes.hasAvailableCode(tenantId, user.id())) {
			factors.add(MfaFactor.RECOVERY_CODE);
		}
		if (!factors.isEmpty()) {
			Instant passwordVerifiedAt = this.timeSource.now();
			this.audit.mfaRequired(tenantId, user.id(), source, passwordVerifiedAt, factors);
			return PasswordLoginTransactionResult.mfaRequired(user.id(), passwordVerifiedAt, factors);
		}

		UserSession session = this.sessions.start(tenantId, user.id(), SessionAuthenticationMethod.PASSWORD,
				this.properties.absoluteTtl());
		this.audit.loginSucceeded(session, source, SessionAuthenticationFactorType.PASSWORD);
		return PasswordLoginTransactionResult.authenticated(session);
	}

}
