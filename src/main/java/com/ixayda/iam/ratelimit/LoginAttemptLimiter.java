package com.ixayda.iam.ratelimit;

public interface LoginAttemptLimiter {

	LoginAttemptDecision acquire(LoginAttemptKey key);

	void recordSuccess(LoginAttemptKey key);

}
