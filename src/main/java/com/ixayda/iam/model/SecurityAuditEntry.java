package com.ixayda.iam.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A persisted event with its database recording time and stored outcome. */
public record SecurityAuditEntry(UUID id, SecurityAuditEvent.Action action, Outcome outcome, UUID targetUserId,
		SecurityAuditContext context, Instant recordedAt) {

	public SecurityAuditEntry {
		Objects.requireNonNull(id, "Audit event id is required");
		Objects.requireNonNull(action, "Audit action is required");
		Objects.requireNonNull(outcome, "Audit outcome is required");
		Objects.requireNonNull(context, "Audit context is required");
		Objects.requireNonNull(recordedAt, "Audit recording time is required");
	}

	public enum Outcome {
		SUCCESS, FAILURE
	}

}
