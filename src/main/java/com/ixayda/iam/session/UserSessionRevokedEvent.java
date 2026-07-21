package com.ixayda.iam.session;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record UserSessionRevokedEvent(TenantId tenantId, UserId userId, SessionId sessionId, Instant occurredAt) {

	public UserSessionRevokedEvent {
		Objects.requireNonNull(tenantId, "Session revocation event tenant ID must not be null");
		Objects.requireNonNull(userId, "Session revocation event user ID must not be null");
		Objects.requireNonNull(sessionId, "Session revocation event session ID must not be null");
		Objects.requireNonNull(occurredAt, "Session revocation event time must not be null");
	}

}
