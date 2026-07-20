package com.ixayda.iam.session;

import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface SessionOperations {

	/**
	 * Starts a session inside the caller's existing authentication transaction.
	 */
	UserSession start(TenantId tenantId, UserId userId, SessionAuthenticationMethod authenticationMethod,
			SessionAbsoluteTtl absoluteTtl);

	/**
	 * Starts a session with independently timestamped authentication factors inside the
	 * caller's existing authentication transaction.
	 */
	UserSession start(TenantId tenantId, UserId userId, SessionAuthenticationMethod authenticationMethod,
			Set<SessionAuthenticationFactor> authenticationFactors, SessionAbsoluteTtl absoluteTtl);

	Optional<UserSession> findById(TenantId tenantId, SessionId sessionId);

	/**
	 * Returns a session only when its time, status, tenant, user, and lifecycle
	 * snapshots are currently usable. This is a point-in-time read and must not be
	 * used as the authorization guard for a later write.
	 */
	Optional<UserSession> findUsable(TenantId tenantId, SessionId sessionId);

	UserSession revoke(TenantId tenantId, SessionId sessionId);

}
