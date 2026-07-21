package com.ixayda.iam.audit;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public record AuditEventExportQuery(Instant fromRecordedAt, Instant toRecordedAt, int limit, AuditEventId after) {

	public static final int MAXIMUM_LIMIT = 1_000;

	public static final Duration MAXIMUM_WINDOW = Duration.ofDays(31);

	public AuditEventExportQuery {
		Objects.requireNonNull(fromRecordedAt, "Audit export start time must not be null");
		Objects.requireNonNull(toRecordedAt, "Audit export end time must not be null");
		if (!fromRecordedAt.isBefore(toRecordedAt)
				|| Duration.between(fromRecordedAt, toRecordedAt).compareTo(MAXIMUM_WINDOW) > 0) {
			throw new IllegalArgumentException("Audit export time window must be positive and at most 31 days");
		}
		if (limit < 1 || limit > MAXIMUM_LIMIT) {
			throw new IllegalArgumentException("Audit export limit must be between 1 and 1000");
		}
	}

}
