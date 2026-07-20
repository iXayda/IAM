package com.ixayda.iam.auth.internal;

import java.util.Objects;

import com.ixayda.iam.auth.LocalPasswordLoginOperations;
import com.ixayda.iam.auth.LocalPasswordLoginResult;
import com.ixayda.iam.auth.MfaChallengeIssue;
import com.ixayda.iam.auth.MfaChallengeOperations;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptDecision;
import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptLease;
import com.ixayda.iam.ratelimit.LoginAttemptLimiter;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
class DefaultLocalPasswordLoginOperations implements LocalPasswordLoginOperations {

	private static final Logger logger = LoggerFactory.getLogger(DefaultLocalPasswordLoginOperations.class);

	private final LoginAttemptLimiter limiter;

	private final TransactionalLocalPasswordLogin transactionalLogin;

	private final MfaChallengeOperations challenges;

	DefaultLocalPasswordLoginOperations(LoginAttemptLimiter limiter,
			TransactionalLocalPasswordLogin transactionalLogin, MfaChallengeOperations challenges) {
		this.limiter = limiter;
		this.transactionalLogin = transactionalLogin;
		this.challenges = challenges;
	}

	@Override
	public LocalPasswordLoginResult login(TenantId tenantId, LoginKey loginKey, LoginAttemptSource source,
			PasswordAttempt password) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(loginKey, "Login key must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
		Objects.requireNonNull(password, "Password attempt must not be null");
		requireNoTransaction();

		LoginAttemptKey attemptKey = new LoginAttemptKey(tenantId, loginKey, source);
		LoginAttemptDecision decision = this.limiter.acquire(attemptKey);
		return switch (decision.status()) {
			case ALLOWED -> authenticate(attemptKey, decision, password);
			case THROTTLED -> LocalPasswordLoginResult.throttled(decision.retryAfter().orElseThrow());
			case UNAVAILABLE -> LocalPasswordLoginResult.unavailable();
		};
	}

	private LocalPasswordLoginResult authenticate(LoginAttemptKey attemptKey, LoginAttemptDecision decision,
			PasswordAttempt password) {
		LoginAttemptLease lease = decision.lease().orElseThrow();
		PasswordLoginTransactionResult transaction = this.transactionalLogin.authenticate(attemptKey.tenantId(),
				attemptKey.loginKey(), password);
		LocalPasswordLoginResult result = result(attemptKey, transaction);
		if (result.authenticated() || result.mfaRequired()) {
			recordSuccess(attemptKey, lease);
		}
		return result;
	}

	private LocalPasswordLoginResult result(LoginAttemptKey attemptKey, PasswordLoginTransactionResult transaction) {
		if (transaction.authenticated()) {
			return LocalPasswordLoginResult.success(transaction.session().orElseThrow());
		}
		if (!transaction.mfaRequired()) {
			return LocalPasswordLoginResult.rejected();
		}
		MfaChallengeIssue issue = this.challenges.issue(attemptKey.tenantId(), transaction.userId().orElseThrow(),
				attemptKey.source(), transaction.passwordVerifiedAt().orElseThrow(), transaction.factors());
		return issue.issued() ? LocalPasswordLoginResult.mfaRequired(issue.challenge().orElseThrow())
				: LocalPasswordLoginResult.unavailable();
	}

	private void recordSuccess(LoginAttemptKey attemptKey, LoginAttemptLease lease) {
		try {
			this.limiter.recordSuccess(attemptKey, lease);
		}
		catch (RuntimeException exception) {
			logger.warn("Login rate-limit success acknowledgement failed after accepted login step; failure_type={}",
					exception.getClass().getName());
		}
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException(
					"Local password login must not run inside a database transaction");
		}
	}

}
