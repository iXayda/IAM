package com.ixayda.iam.ratelimit;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;

/**
 * Tenant-scoped login principal and its canonical trusted ingress source.
 */
public record LoginAttemptKey(TenantId tenantId, LoginKey loginKey, LoginAttemptSource source) {

	public LoginAttemptKey {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(loginKey, "Login key must not be null");
		Objects.requireNonNull(source, "Login attempt source must not be null");
	}

	@Override
	public String toString() {
		return "LoginAttemptKey[tenantId=" + this.tenantId + ", loginKey=redacted, source=redacted]";
	}

}
