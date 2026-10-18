package com.ixayda.iam.model;

import java.time.Instant;
import java.util.UUID;

/** Optional exact-match criteria and a half-open recording-time interval. */
public record SecurityAuditFilter(Instant fromInclusive, Instant untilExclusive, SecurityAuditEvent.Action action,
		SecurityAuditEntry.Outcome outcome, String actor, String source, UUID targetUserId, UUID correlationId) {

	private static final Instant MIN_TIME = Instant.parse("-4712-01-01T00:00:00Z");

	private static final Instant END_TIME = Instant.parse("+294277-01-01T00:00:00Z");

	public SecurityAuditFilter {
		validateTime(fromInclusive);
		validateTime(untilExclusive);
		if (fromInclusive != null && untilExclusive != null && !fromInclusive.isBefore(untilExclusive)) {
			throw new IllegalArgumentException("Audit start time must precede end time");
		}
		if (actor != null && !actor.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")) {
			throw new IllegalArgumentException("Audit actor filter is invalid");
		}
		if (source != null && !source.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}")) {
			throw new IllegalArgumentException("Audit source filter is invalid");
		}
	}

	/** Finite PostgreSQL timestamps; no infinity sentinel is accepted by the query API. */
	static void validateTime(Instant time) {
		if (time != null && (time.isBefore(MIN_TIME) || !time.isBefore(END_TIME))) {
			throw new IllegalArgumentException("Audit time is outside the supported range");
		}
	}

}
