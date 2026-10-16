package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** A successful identity operation to append; PostgreSQL assigns its recording time. */
public record SecurityAuditEvent(UUID id, Action action, UUID targetUserId, SecurityAuditContext context) {

	public SecurityAuditEvent {
		Objects.requireNonNull(id, "Audit event id is required");
		Objects.requireNonNull(action, "Audit action is required");
		Objects.requireNonNull(targetUserId, "Audit target user id is required");
		Objects.requireNonNull(context, "Audit context is required");
	}

	public enum Action {
		USER_CREATED, INITIAL_PASSWORD_SET, ACCOUNT_SETUP_ISSUED, ACCOUNT_SETUP_CANCELLED, ACCOUNT_SETUP_COMPLETED
	}

}
