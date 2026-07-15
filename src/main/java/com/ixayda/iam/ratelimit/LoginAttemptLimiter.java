package com.ixayda.iam.ratelimit;

public interface LoginAttemptLimiter {

	/**
	 * Atomically consumes the principal and trusted-source budgets. Both throttled
	 * and unavailable decisions must stop authentication.
	 */
	LoginAttemptDecision acquire(LoginAttemptKey key);

	/**
	 * Acknowledges an allowed attempt only after its authentication transaction has
	 * committed. A stale lease is ignored so an earlier success cannot clear later
	 * attempts. Operational reset failures must not escape to the caller.
	 */
	void recordSuccess(LoginAttemptKey key, LoginAttemptLease lease);

}
