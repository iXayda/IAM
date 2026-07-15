package com.ixayda.iam.securitystate;

import java.time.Duration;

public interface SecurityStateOperations {

	/**
	 * Issues one tenant-, purpose-, and binding-scoped bearer token with a bounded
	 * lifetime. Multiple independently consumable tokens may coexist for the same key;
	 * callers are responsible for issuance policy and rate limits. An unavailable
	 * result must stop the protected flow.
	 */
	SecurityStateIssue issue(SecurityStateKey key, Duration timeToLive);

	/**
	 * Atomically consumes one token. Missing, expired, replayed, or incorrectly bound
	 * tokens all return the same rejected status. Consumption is at-most-once; callers
	 * must issue a new token if protected work fails after consumption.
	 */
	SecurityStateConsumeStatus consume(SecurityStateKey key, SecurityStateToken token);

}
