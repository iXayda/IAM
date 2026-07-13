package com.ixayda.iam.auth;

import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;

public interface LocalPasswordLoginOperations {

	/**
	 * Authenticates a local user and starts its session atomically. The caller retains
	 * ownership of {@code password} and should close it after this method returns.
	 */
	LocalPasswordLoginResult login(TenantId tenantId, LoginKey loginKey, PasswordAttempt password);

}
