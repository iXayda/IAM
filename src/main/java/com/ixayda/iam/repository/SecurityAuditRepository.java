package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEntry;
import com.ixayda.iam.model.SecurityAuditEvent;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.model.SecurityAuditPage;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class SecurityAuditRepository {

	private final JdbcClient jdbc;

	SecurityAuditRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public List<SecurityAuditEntry> search(SecurityAuditFilter filter, int limit, SecurityAuditPage.Cursor after) {
		var sql = new StringBuilder("""
				SELECT id, actor, source, correlation_id, target_user_id, action, outcome, recorded_at
				FROM iam_security_audit WHERE 1 = 1
				""");
		var parameters = new HashMap<String, Object>();
		if (filter.fromInclusive() != null) {
			// Stored times have microsecond resolution; preserve nanosecond boundary semantics.
			sql.append(filter.fromInclusive().getNano() % 1_000 == 0 ? " AND recorded_at >= :from" : " AND recorded_at > :from");
			parameters.put("from", sqlTime(filter.fromInclusive()));
		}
		if (filter.untilExclusive() != null) {
			sql.append(filter.untilExclusive().getNano() % 1_000 == 0 ? " AND recorded_at < :until" : " AND recorded_at <= :until");
			parameters.put("until", sqlTime(filter.untilExclusive()));
		}
		if (filter.action() != null) {
			sql.append(" AND action = :action");
			parameters.put("action", filter.action().name().toLowerCase(Locale.ROOT));
		}
		if (filter.outcome() != null) {
			sql.append(" AND outcome = :outcome");
			parameters.put("outcome", filter.outcome().name().toLowerCase(Locale.ROOT));
		}
		if (filter.actor() != null) {
			sql.append(" AND actor = :actor");
			parameters.put("actor", filter.actor());
		}
		if (filter.source() != null) {
			sql.append(" AND source = :source");
			parameters.put("source", filter.source());
		}
		if (filter.targetUserId() != null) {
			sql.append(" AND target_user_id = :target");
			parameters.put("target", filter.targetUserId());
		}
		if (filter.correlationId() != null) {
			sql.append(" AND correlation_id = :correlation");
			parameters.put("correlation", filter.correlationId());
		}
		if (after != null) {
			sql.append(" AND (recorded_at, id) < (:recordedAt, :id)");
			parameters.put("recordedAt", sqlTime(after.recordedAt()));
			parameters.put("id", after.id());
		}
		sql.append(" ORDER BY recorded_at DESC, id DESC LIMIT :limit");
		parameters.put("limit", limit);
		return this.jdbc.sql(sql.toString()).params(parameters).query(SecurityAuditRepository::mapEntry).list();
	}

	private static OffsetDateTime sqlTime(Instant time) {
		return OffsetDateTime.ofInstant(time.truncatedTo(ChronoUnit.MICROS), ZoneOffset.UTC);
	}

	private static SecurityAuditEntry mapEntry(ResultSet result, int row) throws SQLException {
		return new SecurityAuditEntry(result.getObject("id", UUID.class),
				SecurityAuditEvent.Action.valueOf(result.getString("action").toUpperCase(Locale.ROOT)),
				SecurityAuditEntry.Outcome.valueOf(result.getString("outcome").toUpperCase(Locale.ROOT)),
				result.getObject("target_user_id", UUID.class),
				new SecurityAuditContext(result.getString("actor"), result.getString("source"), result.getObject("correlation_id", UUID.class)),
				result.getObject("recorded_at", OffsetDateTime.class).toInstant());
	}

	public void append(SecurityAuditEvent event) {
		int inserted = this.jdbc.sql("""
				INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
				VALUES (:id, :actor, :source, :correlationId, :targetUserId, :action, :outcome)
				""").param("id", event.id()).param("actor", event.context().actor())
				.param("source", event.context().source()).param("correlationId", event.context().correlationId())
				.param("targetUserId", event.targetUserId()).param("action", event.action().name().toLowerCase(Locale.ROOT))
				.param("outcome", event.action().isFailure() ? "failure" : "success")
				.update();
		if (inserted != 1) {
			throw new IllegalStateException("Audit event was not stored");
		}
		boolean matches = this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_security_audit
				    WHERE id=:id AND actor=:actor AND source=:source AND correlation_id=:correlationId
				      AND target_user_id IS NOT DISTINCT FROM :targetUserId AND action=:action AND outcome=:outcome)
				""").param("id", event.id()).param("actor", event.context().actor()).param("source", event.context().source())
				.param("correlationId", event.context().correlationId()).param("targetUserId", event.targetUserId())
				.param("action", event.action().name().toLowerCase(Locale.ROOT)).param("outcome", event.action().isFailure() ? "failure" : "success").query(Boolean.class).single();
		if (!matches) { throw new IllegalStateException("Audit event does not match stored state"); }
	}

}
