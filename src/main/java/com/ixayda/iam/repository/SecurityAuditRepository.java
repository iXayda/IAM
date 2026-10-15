package com.ixayda.iam.repository;

import java.util.Locale;

import com.ixayda.iam.model.SecurityAuditEvent;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class SecurityAuditRepository {

	private final JdbcClient jdbc;

	SecurityAuditRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public void append(SecurityAuditEvent event) {
		int inserted = this.jdbc.sql("""
				INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
				VALUES (:id, :actor, :source, :correlationId, :targetUserId, :action, 'success')
				""").param("id", event.id()).param("actor", event.context().actor())
				.param("source", event.context().source()).param("correlationId", event.context().correlationId())
				.param("targetUserId", event.targetUserId()).param("action", event.action().name().toLowerCase(Locale.ROOT))
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
				.param("action", event.action().name().toLowerCase(Locale.ROOT)).param("outcome", "success").query(Boolean.class).single();
		if (!matches) { throw new IllegalStateException("Audit event does not match stored state"); }
	}

}
