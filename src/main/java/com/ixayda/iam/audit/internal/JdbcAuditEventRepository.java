package com.ixayda.iam.audit.internal;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditAuthenticationFactor;
import com.ixayda.iam.audit.AuditEvent;
import com.ixayda.iam.audit.AuditEventId;
import com.ixayda.iam.audit.AuditEventOutcome;
import com.ixayda.iam.audit.AuditEventPage;
import com.ixayda.iam.audit.AuditEventQuery;
import com.ixayda.iam.audit.AuditEventType;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class JdbcAuditEventRepository {

	private static final String COLUMNS = """
			event_id, tenant_id, event_type, outcome, actor_user_id, user_id, session_id,
			authentication_factor, source, attributes::text AS attributes, occurred_at, recorded_at
			""";

	private final JdbcClient jdbcClient;

	private final AuditEventJsonCodec jsonCodec;

	JdbcAuditEventRepository(JdbcClient jdbcClient, AuditEventJsonCodec jsonCodec) {
		this.jdbcClient = jdbcClient;
		this.jsonCodec = jsonCodec;
	}

	AuditEvent append(AppendAuditEvent event) {
		InsertedEvent inserted = this.jdbcClient.sql("""
				INSERT INTO audit_events (
				    tenant_id, event_type, outcome, actor_user_id, user_id, session_id,
				    authentication_factor, source, attributes, occurred_at
				)
				VALUES (
				    :tenantId, :eventType, :outcome, :actorUserId, :userId, :sessionId,
				    :authenticationFactor, :source, CAST(:attributes AS jsonb), :occurredAt
				)
				RETURNING event_id, recorded_at
				""")
			.param("tenantId", event.tenantId().value())
			.param("eventType", event.type().value())
			.param("outcome", databaseValue(event.outcome()))
			.param("actorUserId", event.actorUserId() == null ? null : event.actorUserId().value())
			.param("userId", event.userId() == null ? null : event.userId().value())
			.param("sessionId", event.sessionId() == null ? null : event.sessionId().value())
			.param("authenticationFactor", databaseValue(event.authenticationFactor()))
			.param("source", event.source())
			.param("attributes", this.jsonCodec.write(event.attributes()))
			.param("occurredAt", databaseValue(event.occurredAt()))
			.query((resultSet, rowNumber) -> new InsertedEvent(
					new AuditEventId(resultSet.getObject("event_id", java.util.UUID.class)),
					resultSet.getObject("recorded_at", OffsetDateTime.class).toInstant()))
			.single();
		return new AuditEvent(inserted.id(), event.tenantId(), event.type(), event.outcome(), event.actorUserId(),
				event.userId(), event.sessionId(), event.authenticationFactor(), event.source(), event.occurredAt(),
				inserted.recordedAt(), event.attributes());
	}

	AuditEventPage find(TenantId tenantId, AuditEventQuery query) {
		AuditCursor cursor = null;
		if (query.before() != null) {
			Optional<AuditCursor> found = findCursor(tenantId, query.before());
			if (found.isEmpty()) {
				return new AuditEventPage(List.of(), null);
			}
			cursor = found.orElseThrow();
		}
		List<AuditEvent> events = cursor == null ? firstPage(tenantId, query.limit() + 1)
				: nextPage(tenantId, cursor, query.limit() + 1);
		if (events.size() <= query.limit()) {
			return new AuditEventPage(events, null);
		}
		List<AuditEvent> page = List.copyOf(events.subList(0, query.limit()));
		return new AuditEventPage(page, page.getLast().id());
	}

	private Optional<AuditCursor> findCursor(TenantId tenantId, AuditEventId eventId) {
		return this.jdbcClient.sql("""
				SELECT occurred_at, event_id
				FROM audit_events
				WHERE tenant_id = :tenantId AND event_id = :eventId
				""")
			.param("tenantId", tenantId.value())
			.param("eventId", eventId.value())
			.query((resultSet, rowNumber) -> new AuditCursor(
					resultSet.getObject("occurred_at", OffsetDateTime.class).toInstant(),
					new AuditEventId(resultSet.getObject("event_id", java.util.UUID.class))))
			.optional();
	}

	private List<AuditEvent> firstPage(TenantId tenantId, int limit) {
		return this.jdbcClient.sql("SELECT " + COLUMNS + """
				FROM audit_events
				WHERE tenant_id = :tenantId
				ORDER BY occurred_at DESC, event_id DESC
				LIMIT :limit
				""")
			.param("tenantId", tenantId.value())
			.param("limit", limit)
			.query(this::map)
			.list();
	}

	private List<AuditEvent> nextPage(TenantId tenantId, AuditCursor cursor, int limit) {
		return this.jdbcClient.sql("SELECT " + COLUMNS + """
				FROM audit_events
				WHERE tenant_id = :tenantId
				  AND (occurred_at, event_id) < (:occurredAt, :eventId)
				ORDER BY occurred_at DESC, event_id DESC
				LIMIT :limit
				""")
			.param("tenantId", tenantId.value())
			.param("occurredAt", databaseValue(cursor.occurredAt()))
			.param("eventId", cursor.eventId().value())
			.param("limit", limit)
			.query(this::map)
			.list();
	}

	private AuditEvent map(ResultSet resultSet, int rowNumber) throws SQLException {
		try {
			return new AuditEvent(new AuditEventId(resultSet.getObject("event_id", java.util.UUID.class)),
					new TenantId(resultSet.getObject("tenant_id", java.util.UUID.class)),
					AuditEventType.from(resultSet.getString("event_type")),
					AuditEventOutcome.valueOf(resultSet.getString("outcome").toUpperCase(Locale.ROOT)),
					userId(resultSet, "actor_user_id"), userId(resultSet, "user_id"), sessionId(resultSet),
					factor(resultSet.getString("authentication_factor")),
					resultSet.getString("source"),
					resultSet.getObject("occurred_at", OffsetDateTime.class).toInstant(),
					resultSet.getObject("recorded_at", OffsetDateTime.class).toInstant(),
					this.jsonCodec.read(resultSet.getString("attributes")));
		}
		catch (IllegalArgumentException exception) {
			throw new DataRetrievalFailureException("Stored audit event is invalid", exception);
		}
	}

	private static UserId userId(ResultSet resultSet, String column) throws SQLException {
		java.util.UUID value = resultSet.getObject(column, java.util.UUID.class);
		return value == null ? null : new UserId(value);
	}

	private static SessionId sessionId(ResultSet resultSet) throws SQLException {
		java.util.UUID value = resultSet.getObject("session_id", java.util.UUID.class);
		return value == null ? null : new SessionId(value);
	}

	private static AuditAuthenticationFactor factor(String value) {
		return value == null ? null : AuditAuthenticationFactor.valueOf(value.toUpperCase(Locale.ROOT));
	}

	private static String databaseValue(Enum<?> value) {
		return value == null ? null : value.name().toLowerCase(Locale.ROOT);
	}

	private static OffsetDateTime databaseValue(Instant value) {
		return OffsetDateTime.ofInstant(value, ZoneOffset.UTC);
	}

	private record AuditCursor(Instant occurredAt, AuditEventId eventId) {
	}

	private record InsertedEvent(AuditEventId id, Instant recordedAt) {
	}

}
