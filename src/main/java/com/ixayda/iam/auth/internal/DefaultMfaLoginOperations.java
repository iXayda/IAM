package com.ixayda.iam.auth.internal;

import java.util.Objects;
import java.util.function.Supplier;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeConsumeStatus;
import com.ixayda.iam.auth.MfaChallengeOperations;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.auth.MfaLoginOperations;
import com.ixayda.iam.auth.MfaLoginResult;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
class DefaultMfaLoginOperations implements MfaLoginOperations {

	private final MfaChallengeOperations challenges;

	private final TransactionalMfaLogin transactionalLogin;

	private final AuthenticationAuditRecorder audit;

	DefaultMfaLoginOperations(MfaChallengeOperations challenges, TransactionalMfaLogin transactionalLogin,
			AuthenticationAuditRecorder audit) {
		this.challenges = challenges;
		this.transactionalLogin = transactionalLogin;
		this.audit = audit;
	}

	@Override
	public MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, TotpCodeAttempt code) {
		Objects.requireNonNull(code, "TOTP code attempt must not be null");
		return complete(challenge, source, MfaFactor.TOTP,
				() -> this.transactionalLogin.complete(challenge, source, code));
	}

	@Override
	public MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, RecoveryCodeAttempt code) {
		Objects.requireNonNull(code, "Recovery code attempt must not be null");
		return complete(challenge, source, MfaFactor.RECOVERY_CODE,
				() -> this.transactionalLogin.complete(challenge, source, code));
	}

	private MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, MfaFactor factor,
			Supplier<MfaLoginResult> completion) {
		Objects.requireNonNull(challenge, "MFA challenge must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		requireNoTransaction();
		MfaChallengeConsumeStatus status = this.challenges.consume(challenge, source);
		if (status == MfaChallengeConsumeStatus.UNAVAILABLE) {
			this.audit.mfaUnavailable(challenge, source, factor, "challenge_state");
			return MfaLoginResult.unavailable();
		}
		if (status == MfaChallengeConsumeStatus.REJECTED || !challenge.supports(factor)) {
			this.audit.mfaFailed(challenge, source, factor, "invalid_challenge");
			return MfaLoginResult.rejected();
		}
		return completion.get();
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException("MFA login completion must start outside a database transaction");
		}
	}

}
