package com.ixayda.iam.user.internal;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.UserId;

final class UserProviderAlreadyLinkedException extends RuntimeException {

	private final TenantId tenantId;

	private final ExternalIdentityProviderId providerId;

	private final UserId userId;

	UserProviderAlreadyLinkedException(TenantId tenantId, ExternalIdentityProviderId providerId, UserId userId) {
		super("A user is already linked for provider " + providerId + " in tenant " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.providerId = Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	ExternalIdentityProviderId providerId() {
		return this.providerId;
	}

	UserId userId() {
		return this.userId;
	}

}
