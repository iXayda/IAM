package com.ixayda.iam.audit;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditEventSchemaIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private JdbcClient jdbcClient;

	@Test
	void rejectsUpdatesDeletesAndTruncation() {
		UUID eventId = insertEvent();

		assertThatThrownBy(() -> this.jdbcClient.sql("UPDATE audit_events SET outcome = 'succeeded'")
			.update()).isInstanceOf(DataAccessException.class).hasMessageContaining("audit_events is append-only");
		assertThatThrownBy(() -> this.jdbcClient.sql("DELETE FROM audit_events WHERE event_id = :eventId")
			.param("eventId", eventId)
			.update()).isInstanceOf(DataAccessException.class).hasMessageContaining("audit_events is append-only");
		assertThatThrownBy(() -> this.jdbcClient.sql("TRUNCATE audit_events")
			.update()).isInstanceOf(DataAccessException.class).hasMessageContaining("audit_events is append-only");
		assertThat(this.jdbcClient.sql("SELECT count(*) FROM audit_events WHERE event_id = :eventId")
			.param("eventId", eventId)
			.query(Integer.class)
			.single()).isOne();
	}

	@Test
	void enforcesEventShapesWithoutIdentityForeignKeys() {
		UUID actorUserId = UUID.randomUUID();
		UUID eventId = this.jdbcClient.sql("""
				INSERT INTO audit_events (
				    event_id, tenant_id, event_type, outcome, actor_user_id, source, attributes, occurred_at
				)
				VALUES (:eventId, :tenantId, 'administration.role.granted', 'succeeded', :actorUserId,
				        'administration', '{}'::jsonb, :occurredAt)
				RETURNING event_id
				""")
			.param("eventId", UUID.randomUUID())
			.param("tenantId", UUID.randomUUID())
			.param("actorUserId", actorUserId)
			.param("occurredAt", OffsetDateTime.now(ZoneOffset.UTC))
			.query(UUID.class)
			.single();
		assertThat(this.jdbcClient.sql("SELECT actor_user_id FROM audit_events WHERE event_id = :eventId")
			.param("eventId", eventId)
			.query(UUID.class)
			.single()).isEqualTo(actorUserId);

		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO audit_events (
				    event_id, tenant_id, event_type, outcome, source, attributes, occurred_at
				)
				VALUES (:eventId, :tenantId, 'invalid', 'unknown', 'source with spaces', '[]'::jsonb, :occurredAt)
				""")
			.param("eventId", UUID.randomUUID())
			.param("tenantId", UUID.randomUUID())
			.param("occurredAt", OffsetDateTime.now(ZoneOffset.UTC))
			.update()).isInstanceOf(DataAccessException.class);
	}

	private UUID insertEvent() {
		UUID eventId = UUID.randomUUID();
		int inserted = this.jdbcClient.sql("""
				INSERT INTO audit_events (
				    event_id, tenant_id, event_type, outcome, source, attributes, occurred_at
				)
				VALUES (
				    :eventId, :tenantId, 'authentication.password.failed', 'failed',
				    'integration:test', '{"reason":"invalid_credentials"}'::jsonb, :occurredAt
				)
				""")
			.param("eventId", eventId)
			.param("tenantId", UUID.randomUUID())
			.param("occurredAt", OffsetDateTime.now(ZoneOffset.UTC))
			.update();
		assertThat(inserted).isOne();
		return eventId;
	}

}
