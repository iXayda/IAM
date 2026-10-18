package com.ixayda.iam.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** A bounded audit listing ordered newest first. */
public record SecurityAuditPage(List<SecurityAuditEntry> items, Cursor nextCursor) {

	public SecurityAuditPage {
		items = List.copyOf(items);
	}

	/** Reused with the same criteria; the position does not confer access to audit records. */
	public record Cursor(Instant recordedAt, UUID id, SecurityAuditFilter filter) {

		public Cursor {
			Objects.requireNonNull(recordedAt, "Cursor recording time is required");
			Objects.requireNonNull(id, "Cursor event id is required");
			Objects.requireNonNull(filter, "Cursor audit filter is required");
			SecurityAuditFilter.validateTime(recordedAt);
			if (recordedAt.getNano() % 1_000 != 0) {
				throw new IllegalArgumentException("Cursor recording time requires microsecond precision");
			}
		}

	}

}
