package com.ixayda.iam.audit;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record AuditEventExportPage(List<AuditEvent> events, AuditEventId nextCursor) {

	public AuditEventExportPage {
		Objects.requireNonNull(events, "Audit export events must not be null");
		events = List.copyOf(events);
		if (events.isEmpty() && nextCursor != null) {
			throw new IllegalArgumentException("Empty audit export pages must not have a cursor");
		}
	}

	public Optional<AuditEventId> next() {
		return Optional.ofNullable(this.nextCursor);
	}

}
