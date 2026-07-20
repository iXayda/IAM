package com.ixayda.iam.audit;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;

import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record AuditEvent(AuditEventId id, TenantId tenantId, AuditEventType type, AuditEventOutcome outcome,
		UserId userId, SessionId sessionId, AuditAuthenticationFactor authenticationFactor, String source,
		Instant occurredAt, Instant recordedAt, Map<String, String> attributes) {

	public AuditEvent {
		Objects.requireNonNull(id, "Audit event ID must not be null");
		AppendAuditEvent validated = new AppendAuditEvent(tenantId, type, outcome, userId, sessionId,
				authenticationFactor, source, occurredAt, attributes);
		tenantId = validated.tenantId();
		type = validated.type();
		outcome = validated.outcome();
		source = validated.source();
		occurredAt = validated.occurredAt();
		attributes = validated.attributes();
		Objects.requireNonNull(recordedAt, "Audit event recording time must not be null");
		if (recordedAt.isBefore(Instant.EPOCH)) {
			throw new IllegalArgumentException("Audit event recording time must not be before the epoch");
		}
		recordedAt = recordedAt.truncatedTo(ChronoUnit.MICROS);
	}

	@Override
	public String toString() {
		return "AuditEvent[id=" + this.id + ", tenantId=" + this.tenantId + ", type=" + this.type + ", outcome="
				+ this.outcome + ", userId=redacted, sessionId=redacted, authenticationFactor="
				+ this.authenticationFactor + ", source=redacted, occurredAt=" + this.occurredAt + ", recordedAt="
				+ this.recordedAt + ", attributes=redacted]";
	}

}
