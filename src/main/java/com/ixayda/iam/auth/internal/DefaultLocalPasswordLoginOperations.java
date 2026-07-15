package com.ixayda.iam.auth.internal;

import java.util.Objects;

import com.ixayda.iam.auth.LocalPasswordLoginOperations;
import com.ixayda.iam.auth.LocalPasswordLoginResult;
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

	DefaultLocalPasswordLoginOperations(LoginAttemptLimiter limiter,
			TransactionalLocalPasswordLogin transactionalLogin) {
		this.limiter = limiter;
		this.transactionalLogin = transactionalLogin;
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
		LocalPasswordLoginResult result = this.transactionalLogin.authenticate(attemptKey.tenantId(),
				attemptKey.loginKey(), password);
		if (result.authenticated()) {
			recordSuccess(attemptKey, lease);
		}
		return result;
	}

	private void recordSuccess(LoginAttemptKey attemptKey, LoginAttemptLease lease) {
		try {
			this.limiter.recordSuccess(attemptKey, lease);
		}
		catch (RuntimeException exception) {
			logger.warn("Login rate-limit success acknowledgement failed after session commit; failure_type={}",
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
