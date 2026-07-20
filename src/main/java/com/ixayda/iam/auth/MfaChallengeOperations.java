package com.ixayda.iam.auth;

import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface MfaChallengeOperations {

	/**
	 * Issues a source-bound, one-time login challenge after password verification.
	 * An unavailable result must stop the login flow.
	 */
	MfaChallengeIssue issue(TenantId tenantId, UserId userId, LoginAttemptSource source,
			Instant passwordVerifiedAt, Set<MfaFactor> factors);

	/**
	 * Atomically consumes a challenge using the current trusted ingress source. Any
	 * metadata or source mismatch returns the same rejected status.
	 */
	MfaChallengeConsumeStatus consume(MfaChallenge challenge, LoginAttemptSource source);

}
