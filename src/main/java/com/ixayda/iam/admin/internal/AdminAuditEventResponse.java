package com.ixayda.iam.admin.internal;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import com.ixayda.iam.audit.AuditEvent;

record AdminAuditEventResponse(String id, String type, String outcome, String userId, String sessionId,
		String authenticationFactor, String source, Instant occurredAt, Instant recordedAt,
		Map<String, String> attributes) {

	AdminAuditEventResponse {
		Objects.requireNonNull(id, "Admin audit event ID must not be null");
		Objects.requireNonNull(type, "Admin audit event type must not be null");
		Objects.requireNonNull(outcome, "Admin audit event outcome must not be null");
		Objects.requireNonNull(source, "Admin audit event source must not be null");
		Objects.requireNonNull(occurredAt, "Admin audit event occurrence time must not be null");
		Objects.requireNonNull(recordedAt, "Admin audit event recording time must not be null");
		Objects.requireNonNull(attributes, "Admin audit event attributes must not be null");
		attributes = Map.copyOf(attributes);
	}

	static AdminAuditEventResponse from(AuditEvent event) {
		Objects.requireNonNull(event, "Audit event must not be null");
		return new AdminAuditEventResponse(event.id().toString(), event.type().value(),
				event.outcome().name().toLowerCase(Locale.ROOT),
				event.userId() == null ? null : event.userId().toString(),
				event.sessionId() == null ? null : event.sessionId().toString(),
				event.authenticationFactor() == null ? null
						: event.authenticationFactor().name().toLowerCase(Locale.ROOT),
				event.source(), event.occurredAt(), event.recordedAt(), event.attributes());
	}

}
