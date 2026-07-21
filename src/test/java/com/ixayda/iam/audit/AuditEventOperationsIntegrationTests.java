package com.ixayda.iam.audit;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditEventOperationsIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private AuditEventOperations events;

	@Test
	void appendsTenantIsolatedEventsAndPagesNewestFirst() {
		TenantId tenantId = new TenantId(UUID.randomUUID());
		TenantId anotherTenant = new TenantId(UUID.randomUUID());
		Instant now = Instant.parse("2026-07-20T00:00:03Z");
		UserId actorUserId = new UserId(UUID.randomUUID());
		AuditEvent oldest = append(tenantId, "authentication.password.failed", AuditEventOutcome.FAILED,
				now.minusSeconds(2));
		AuditEvent middle = append(tenantId, "authentication.mfa.required", AuditEventOutcome.CHALLENGED,
				now.minusSeconds(1));
		AuditEvent newest = this.events.append(new AppendAuditEvent(tenantId,
				AuditEventType.from("administration.role.granted"), AuditEventOutcome.SUCCEEDED, actorUserId, null, null,
				null, "integration:" + UUID.randomUUID(), now, Map.of("role", "auditor")));
		append(anotherTenant, "authentication.login.succeeded", AuditEventOutcome.SUCCEEDED, now.plusSeconds(1));

		AuditEventPage first = this.events.find(tenantId, new AuditEventQuery(2, null));
		AuditEventPage second = this.events.find(tenantId, new AuditEventQuery(2, first.next().orElseThrow()));

		assertThat(first.events()).extracting(AuditEvent::id).containsExactly(newest.id(), middle.id());
		assertThat(first.events()).allSatisfy(event -> assertThat(event.id().value().version()).isEqualTo(7));
		assertThat(first.next()).contains(middle.id());
		assertThat(first.events().getFirst().actorUserId()).isEqualTo(actorUserId);
		assertThat(second.events()).extracting(AuditEvent::id).containsExactly(oldest.id());
		assertThat(second.next()).isEmpty();
		assertThat(this.events.find(anotherTenant, AuditEventQuery.firstPage()).events()).hasSize(1);
	}

	@Test
	void returnsAnEmptyPageForACursorOutsideTheTenant() {
		TenantId tenantId = new TenantId(UUID.randomUUID());
		TenantId anotherTenant = new TenantId(UUID.randomUUID());
		AuditEvent foreign = append(anotherTenant, "authentication.password.failed", AuditEventOutcome.FAILED,
				Instant.parse("2026-07-20T00:00:00Z"));

		AuditEventPage page = this.events.find(tenantId, new AuditEventQuery(10, foreign.id()));

		assertThat(page.events()).isEmpty();
		assertThat(page.next()).isEmpty();
	}

	@Test
	void exportsRecordedEventsOldestFirstWithTenantAndWindowBoundCursors() {
		TenantId tenantId = new TenantId(UUID.randomUUID());
		TenantId anotherTenant = new TenantId(UUID.randomUUID());
		AuditEvent firstInserted = append(tenantId, "authentication.password.failed", AuditEventOutcome.FAILED,
				Instant.parse("2026-07-20T01:00:00Z"));
		AuditEvent secondInserted = append(tenantId, "authentication.login.succeeded", AuditEventOutcome.SUCCEEDED,
				Instant.parse("2026-07-20T00:00:00Z"));
		AuditEvent foreign = append(anotherTenant, "authentication.login.succeeded", AuditEventOutcome.SUCCEEDED,
				Instant.parse("2026-07-20T00:30:00Z"));
		List<AuditEvent> expected = List.of(firstInserted, secondInserted)
			.stream()
			.sorted(Comparator.comparing(AuditEvent::recordedAt).thenComparing(event -> event.id().value()))
			.toList();
		Instant from = expected.getFirst().recordedAt();
		Instant to = expected.getLast().recordedAt().plus(1, ChronoUnit.MICROS);

		AuditEventExportPage first = this.events.export(tenantId,
				new AuditEventExportQuery(from, to, 1, null));
		AuditEventExportPage second = this.events.export(tenantId,
				new AuditEventExportQuery(from, to, 1, first.next().orElseThrow()));
		assertThat(first.events()).extracting(AuditEvent::id).containsExactly(expected.getFirst().id());
		assertThat(first.next()).contains(expected.getFirst().id());
		assertThat(second.events()).extracting(AuditEvent::id).containsExactly(expected.getLast().id());
		assertThat(second.next()).isEmpty();
		assertThatThrownBy(() -> this.events.export(tenantId,
				new AuditEventExportQuery(from, foreign.recordedAt().plus(1, ChronoUnit.MICROS), 10, foreign.id())))
			.isInstanceOf(InvalidAuditEventExportCursorException.class);
		assertThatThrownBy(() -> this.events.export(tenantId,
				new AuditEventExportQuery(to, to.plusSeconds(1), 10, firstInserted.id())))
			.isInstanceOf(InvalidAuditEventExportCursorException.class);
	}

	private AuditEvent append(TenantId tenantId, String type, AuditEventOutcome outcome, Instant occurredAt) {
		return this.events.append(new AppendAuditEvent(tenantId, AuditEventType.from(type), outcome, null, null, null,
				"integration:" + UUID.randomUUID(), occurredAt, Map.of("channel", "web")));
	}

}
