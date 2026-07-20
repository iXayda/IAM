package com.ixayda.iam.audit;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditEventDomainTests {

	private static final Instant NOW = Instant.parse("2026-07-20T00:00:00.123456789Z");

	@Test
	void validatesAndCopiesAppendCommands() {
		Map<String, String> attributes = new LinkedHashMap<>();
		attributes.put("reason", "invalid_credentials");
		AppendAuditEvent event = new AppendAuditEvent(TenantId.DEFAULT,
				AuditEventType.from("authentication.password.failed"), AuditEventOutcome.FAILED, null, null,
				AuditAuthenticationFactor.PASSWORD, "remote:203.0.113.9", NOW, attributes);
		attributes.clear();

		assertThat(event.occurredAt()).isEqualTo(Instant.parse("2026-07-20T00:00:00.123456Z"));
		assertThat(event.attributes()).containsOnlyKeys("reason");
		assertThat(event.toString()).contains("userId=redacted", "sessionId=redacted", "source=redacted",
				"attributes=redacted").doesNotContain("203.0.113.9", "invalid_credentials");
	}

	@Test
	void rejectsMalformedTypesSourcesTimesAndAttributes() {
		assertThatThrownBy(() -> AuditEventType.from("invalid")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> event("source with spaces", NOW, Map.of()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> event("source", Instant.EPOCH.minusNanos(1), Map.of()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> event("source", NOW, Map.of("Invalid", "value")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> event("source", NOW, Map.of("reason", "x".repeat(257))))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void boundsQueriesAndExposesOptionalCursors() {
		AuditEventId cursor = AuditEventId.random();
		assertThat(new AuditEventQuery(1, cursor).before()).isEqualTo(cursor);
		assertThat(new AuditEventPage(java.util.List.of(), cursor).next()).contains(cursor);
		assertThatThrownBy(() -> new AuditEventQuery(0, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuditEventQuery(AuditEventQuery.MAXIMUM_LIMIT + 1, null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	private static AppendAuditEvent event(String source, Instant occurredAt, Map<String, String> attributes) {
		return new AppendAuditEvent(TenantId.DEFAULT, AuditEventType.from("authentication.password.failed"),
				AuditEventOutcome.FAILED, null, null, AuditAuthenticationFactor.PASSWORD, source, occurredAt,
				attributes);
	}

}
