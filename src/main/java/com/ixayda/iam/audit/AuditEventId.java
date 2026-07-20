package com.ixayda.iam.audit;

import java.util.Objects;
import java.util.UUID;

public record AuditEventId(UUID value) {

	public AuditEventId {
		Objects.requireNonNull(value, "Audit event ID must not be null");
	}

	public static AuditEventId random() {
		return new AuditEventId(UUID.randomUUID());
	}

	public static AuditEventId from(String value) {
		Objects.requireNonNull(value, "Audit event ID value must not be null");
		return new AuditEventId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
