package com.ixayda.iam.user;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

/**
 * An explicit mapping from a provider-scoped external subject to a local user.
 * The mapping identity is {@code (tenantId, providerId, subjectId)}. Providers
 * must supply a stable, canonical subject; login values must not be used as a
 * substitute. A user can have at most one subject for each provider.
 */
public record UserExternalIdentity(TenantId tenantId, ExternalIdentityProviderId providerId,
		ExternalSubjectId subjectId, UserId userId, Instant linkedAt) {

	public UserExternalIdentity {
		Objects.requireNonNull(tenantId, "External identity tenant ID must not be null");
		Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		Objects.requireNonNull(subjectId, "External identity subject ID must not be null");
		Objects.requireNonNull(userId, "External identity user ID must not be null");
		Objects.requireNonNull(linkedAt, "External identity link time must not be null");
	}

	@Override
	public String toString() {
		return "UserExternalIdentity[tenantId=" + this.tenantId + ", providerId=" + this.providerId
				+ ", subjectId=redacted, userId=" + this.userId + ", linkedAt=" + this.linkedAt + "]";
	}

}
