package com.ixayda.iam.user;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class ExternalIdentityLinkConflictException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	private final ExternalIdentityProviderId providerId;

	public ExternalIdentityLinkConflictException(TenantId tenantId, UserId userId,
			ExternalIdentityProviderId providerId) {
		super("External identity conflicts with an existing mapping for provider " + providerId + " in tenant "
				+ tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.userId = Objects.requireNonNull(userId, "User ID must not be null");
		this.providerId = Objects.requireNonNull(providerId, "External identity provider ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public UserId userId() {
		return this.userId;
	}

	public ExternalIdentityProviderId providerId() {
		return this.providerId;
	}

}
