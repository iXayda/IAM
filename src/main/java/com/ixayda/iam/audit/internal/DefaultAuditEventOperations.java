package com.ixayda.iam.audit.internal;

import java.util.Objects;

import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditEvent;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventPage;
import com.ixayda.iam.audit.AuditEventQuery;
import com.ixayda.iam.tenant.TenantId;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class DefaultAuditEventOperations implements AuditEventOperations {

	private final JdbcAuditEventRepository repository;

	DefaultAuditEventOperations(JdbcAuditEventRepository repository) {
		this.repository = repository;
	}

	@Override
	@Transactional
	public AuditEvent append(AppendAuditEvent event) {
		return this.repository.append(Objects.requireNonNull(event, "Audit event must not be null"));
	}

	@Override
	@Transactional(readOnly = true)
	public AuditEventPage find(TenantId tenantId, AuditEventQuery query) {
		Objects.requireNonNull(tenantId, "Audit event query tenant ID must not be null");
		Objects.requireNonNull(query, "Audit event query must not be null");
		return this.repository.find(tenantId, query);
	}

}
