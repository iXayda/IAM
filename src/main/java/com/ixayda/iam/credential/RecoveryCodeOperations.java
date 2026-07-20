package com.ixayda.iam.credential;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface RecoveryCodeOperations {

	/**
	 * Returns whether the user currently has at least one unconsumed recovery code.
	 * This is a point-in-time query; callers that make a later write must use their own
	 * lifecycle guard.
	 */
	boolean hasAvailableCode(TenantId tenantId, UserId userId);

	/**
	 * Atomically replaces all existing recovery codes and returns the new plaintext
	 * values once. The caller must close the returned set after presenting it.
	 */
	GeneratedRecoveryCodes replace(TenantId tenantId, UserId userId);

	/**
	 * Verifies and atomically consumes one recovery code. The caller must provide a
	 * read-write transaction that remains open through the resulting session or token
	 * write. The caller retains ownership of {@code attempt} and should close it after
	 * this method returns.
	 */
	boolean verifyAndConsume(TenantId tenantId, UserId userId, RecoveryCodeAttempt attempt);

}
