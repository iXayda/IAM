package com.ixayda.iam.securitystate;

import java.time.Duration;

public interface SecurityStateOperations {

	/**
	 * Issues one tenant-, purpose-, and binding-scoped bearer token with a bounded
	 * lifetime. An unavailable result must stop the protected flow.
	 */
	SecurityStateIssue issue(SecurityStateKey key, Duration timeToLive);

	/**
	 * Atomically consumes one token. Missing, expired, replayed, or incorrectly bound
	 * tokens all return the same rejected status.
	 */
	SecurityStateConsumeStatus consume(SecurityStateKey key, SecurityStateToken token);

}
