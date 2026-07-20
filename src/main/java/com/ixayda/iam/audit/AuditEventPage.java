package com.ixayda.iam.audit;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record AuditEventPage(List<AuditEvent> events, AuditEventId nextCursor) {

	public AuditEventPage {
		Objects.requireNonNull(events, "Audit events must not be null");
		events = List.copyOf(events);
	}

	public Optional<AuditEventId> next() {
		return Optional.ofNullable(this.nextCursor);
	}

}
