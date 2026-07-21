package com.ixayda.iam.credential;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface TotpOperations {

	/**
	 * Returns whether the user currently has an active TOTP credential. This is a
	 * point-in-time query; callers that make a later write must use their own lifecycle
	 * guard.
	 */
	boolean hasActiveCredential(TenantId tenantId, UserId userId);

	/**
	 * Replaces any pending enrollment and returns a caller-owned secret that must be
	 * closed after presentation to the user.
	 */
	TotpEnrollment beginEnrollment(TenantId tenantId, UserId userId);

	/**
	 * Activates a pending credential after verifying its first code. A replacement
	 * activation atomically revokes the previous active credential. The caller retains
	 * ownership of {@code code} and should close it after this method returns.
	 */
	boolean activate(TenantId tenantId, UserId userId, TotpCredentialId credentialId, TotpCodeAttempt code);

	/**
	 * Verifies and atomically consumes one TOTP time step. The caller must provide a
	 * read-write transaction that remains open through the resulting session or token
	 * write. The caller retains ownership of {@code code} and should close it after this
	 * method returns.
	 */
	boolean verify(TenantId tenantId, UserId userId, TotpCodeAttempt code);

	/**
	 * Revokes the selected credential and removes its encrypted secret material.
	 */
	boolean revoke(TenantId tenantId, UserId userId, TotpCredentialId credentialId);

	/**
	 * Revokes the user's current active credential, if present, and removes its
	 * encrypted secret material.
	 */
	boolean revokeActive(TenantId tenantId, UserId userId);

}
