package com.ixayda.iam.auth;

import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;

public interface LocalPasswordLoginOperations {

	/**
	 * Applies login-attempt limits, authenticates a local user, and starts its session.
	 * The source must have been canonicalized by a trusted ingress. The caller retains
	 * ownership of {@code password} and should close it after this method returns.
	 */
	LocalPasswordLoginResult login(TenantId tenantId, LoginKey loginKey, LoginAttemptSource source,
			PasswordAttempt password);

}
