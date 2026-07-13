package com.ixayda.iam.user.internal;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;

final class ExternalSubjectAlreadyLinkedException extends RuntimeException {

	private final TenantId tenantId;

	private final ExternalIdentityProviderId providerId;

	ExternalSubjectAlreadyLinkedException(TenantId tenantId, ExternalIdentityProviderId providerId) {
		super("An external subject is already linked for provider " + providerId + " in tenant " + tenantId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.providerId = Objects.requireNonNull(providerId, "External identity provider ID must not be null");
	}

	TenantId tenantId() {
		return this.tenantId;
	}

	ExternalIdentityProviderId providerId() {
		return this.providerId;
	}

}
