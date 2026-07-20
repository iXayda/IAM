package com.ixayda.iam.audit;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record AppendAuditEvent(TenantId tenantId, AuditEventType type, AuditEventOutcome outcome, UserId userId,
		SessionId sessionId, AuditAuthenticationFactor authenticationFactor, String source, Instant occurredAt,
		Map<String, String> attributes) {

	private static final Pattern ATTRIBUTE_NAME = Pattern.compile("[a-z][a-z0-9_]{0,63}");

	public AppendAuditEvent {
		Objects.requireNonNull(tenantId, "Audit event tenant ID must not be null");
		Objects.requireNonNull(type, "Audit event type must not be null");
		Objects.requireNonNull(outcome, "Audit event outcome must not be null");
		source = visibleAscii(source, 512, "Audit event source");
		Objects.requireNonNull(occurredAt, "Audit event occurrence time must not be null");
		if (occurredAt.isBefore(Instant.EPOCH)) {
			throw new IllegalArgumentException("Audit event occurrence time must not be before the epoch");
		}
		occurredAt = occurredAt.truncatedTo(ChronoUnit.MICROS);
		attributes = attributes(attributes);
	}

	private static Map<String, String> attributes(Map<String, String> attributes) {
		Objects.requireNonNull(attributes, "Audit event attributes must not be null");
		if (attributes.size() > 16) {
			throw new IllegalArgumentException("Audit event attributes must not exceed 16 entries");
		}
		Map<String, String> validated = new LinkedHashMap<>();
		attributes.forEach((name, value) -> {
			if (name == null || !ATTRIBUTE_NAME.matcher(name).matches()) {
				throw new IllegalArgumentException("Audit event attribute names must be lowercase identifiers");
			}
			validated.put(name, visibleAscii(value, 256, "Audit event attribute value"));
		});
		return Map.copyOf(validated);
	}

	private static String visibleAscii(String value, int maximumLength, String field) {
		Objects.requireNonNull(value, field + " must not be null");
		if (value.isEmpty() || value.length() > maximumLength
				|| !value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
			throw new IllegalArgumentException(
					field + " must contain 1 to " + maximumLength + " visible ASCII characters");
		}
		return value;
	}

	@Override
	public String toString() {
		return "AppendAuditEvent[tenantId=" + this.tenantId + ", type=" + this.type + ", outcome=" + this.outcome
				+ ", userId=redacted, sessionId=redacted, authenticationFactor=" + this.authenticationFactor
				+ ", source=redacted, occurredAt=" + this.occurredAt + ", attributes=redacted]";
	}

}
