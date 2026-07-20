package com.ixayda.iam.audit;

import com.ixayda.iam.tenant.TenantId;

public interface AuditEventOperations {

	AuditEvent append(AppendAuditEvent event);

	AuditEventPage find(TenantId tenantId, AuditEventQuery query);

}
