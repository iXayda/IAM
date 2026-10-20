package com.ixayda.iam.security;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.SecurityAudits;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Shares mandatory safe rejection audit between transport admission and the native introspection endpoint. */
final class IdentityIntrospectionFailures {

	private static final String RECORDED = IdentityIntrospectionFailures.class.getName() + ".recorded";
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityIntrospectionFailures(SecurityAudits audits, PlatformTransactionManager manager) {
		this.audits = audits; this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	void record(HttpServletRequest request) {
		if (Boolean.TRUE.equals(request.getAttribute(RECORDED))) { return; }
		this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.INTROSPECTION_REJECTED, null,
				new SecurityAuditContext("anonymous", "protocol:introspection", IdentityBrowserDiagnostics.correlationId(request))));
		markRecorded(request);
	}

	void markRecorded(HttpServletRequest request) { request.setAttribute(RECORDED, true); }

}
