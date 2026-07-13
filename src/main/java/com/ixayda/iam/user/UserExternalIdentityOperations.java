package com.ixayda.iam.user;

import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;

public interface UserExternalIdentityOperations {

	/**
	 * Explicitly links a provider-verified subject to an active local user. The caller
	 * must derive the tenant from trusted request context, select the provider that
	 * performed verification, prove control of the subject before this call, and
	 * authorize the target user. This operation performs no external verification and
	 * never links by login value.
	 */
	UserExternalIdentity link(TenantId tenantId, UserId userId, ExternalIdentityProviderId providerId,
			ExternalSubjectId subjectId);

	/**
	 * Returns the stored mapping without evaluating tenant or user activity. Presence
	 * is not an authentication or authorization decision. Authentication callers must
	 * use the mapping in a read-write transaction, call
	 * {@link UserOperations#requireActiveForWrite(TenantId, UserId)}, verify the
	 * returned tenant and user, and hold those locks until the session or token write
	 * commits.
	 */
	Optional<UserExternalIdentity> findBySubject(TenantId tenantId, ExternalIdentityProviderId providerId,
			ExternalSubjectId subjectId);

	/**
	 * Returns the stored mapping without evaluating tenant or user activity. Presence
	 * is not an authentication or authorization decision.
	 */
	Optional<UserExternalIdentity> findByUserAndProvider(TenantId tenantId, UserId userId,
			ExternalIdentityProviderId providerId);

}
