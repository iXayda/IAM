package com.ixayda.iam.authorization.internal;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;

record AuthorizationLoginDetails(Optional<TenantId> tenantId, LoginAttemptSource source) {

	AuthorizationLoginDetails {
		tenantId = Objects.requireNonNull(tenantId, "Tenant ID resolution must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
	}

}
