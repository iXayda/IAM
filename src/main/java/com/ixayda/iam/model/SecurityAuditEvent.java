package com.ixayda.iam.model;

import java.util.Objects;
import java.util.UUID;

/** An identity operation to append; PostgreSQL assigns its recording time. */
public record SecurityAuditEvent(UUID id, Action action, UUID targetUserId, SecurityAuditContext context) {

	public SecurityAuditEvent {
		Objects.requireNonNull(id, "Audit event id is required");
		Objects.requireNonNull(action, "Audit action is required");
		if (targetUserId == null && action.requiresTarget()) {
			throw new IllegalArgumentException("Audit target user id is required");
		}
		Objects.requireNonNull(context, "Audit context is required");
	}

	public enum Action {
		USER_CREATED, INITIAL_PASSWORD_SET, ACCOUNT_SETUP_ISSUED, ACCOUNT_SETUP_CANCELLED, ACCOUNT_SETUP_COMPLETED,
		PASSWORD_AUTHENTICATED, PASSWORD_AUTH_FAILED, PASSWORD_AUTH_THROTTLED,
		BROWSER_SESSION_CREATED, BROWSER_SESSION_ENDED, BROWSER_ENTRY_THROTTLED,
		PASSWORD_CHANGED, PASSWORD_CHANGE_FAILED, PASSWORD_CHANGE_THROTTLED, BROWSER_SESSIONS_REVOKED,
		PASSWORD_RECOVERY_ISSUED, PASSWORD_RECOVERY_CANCELLED, PASSWORD_RECOVERY_COMPLETED, PASSWORD_RECOVERY_FAILED;

		public boolean isFailure() {
			return this == PASSWORD_AUTH_FAILED || this == PASSWORD_AUTH_THROTTLED || this == BROWSER_ENTRY_THROTTLED
					|| this == PASSWORD_CHANGE_FAILED || this == PASSWORD_CHANGE_THROTTLED || this == PASSWORD_RECOVERY_FAILED;
		}

		public boolean requiresTarget() {
			return this != PASSWORD_AUTH_FAILED && this != PASSWORD_AUTH_THROTTLED && this != BROWSER_ENTRY_THROTTLED
					&& this != PASSWORD_RECOVERY_FAILED;
		}
	}

}
