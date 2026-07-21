package com.ixayda.iam.user;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public record UserSecurityEvent(TenantId tenantId, UserId userId, Type type, Instant occurredAt) {

	public UserSecurityEvent {
		Objects.requireNonNull(tenantId, "User security event tenant ID must not be null");
		Objects.requireNonNull(userId, "User security event user ID must not be null");
		Objects.requireNonNull(type, "User security event type must not be null");
		Objects.requireNonNull(occurredAt, "User security event time must not be null");
	}

	public enum Type {

		CREATED,

		ACTIVATED,

		DISABLED,

		LOCKED,

		DELETED

	}

}
