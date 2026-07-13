package com.ixayda.iam.credential;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface PasswordOperations {

	/**
	 * Stores a new password. The caller retains ownership of {@code password} and
	 * should close it after this method returns.
	 */
	void setPassword(TenantId tenantId, UserId userId, NewPassword password);

	/**
	 * Verifies a password. The caller retains ownership of {@code attempt} and should
	 * close it after this method returns. The caller must provide a read-write
	 * transaction that remains open through any resulting session or token write.
	 */
	boolean verifyPassword(TenantId tenantId, UserId userId, PasswordAttempt attempt);

	/**
	 * Performs dummy password hashing at the currently configured work factor when no
	 * stored credential may be consulted. The caller retains ownership of
	 * {@code attempt}.
	 */
	void performDummyVerification(PasswordAttempt attempt);

}
