package com.ixayda.iam.audit;

public record AuditEventQuery(int limit, AuditEventId before) {

	public static final int DEFAULT_LIMIT = 50;

	public static final int MAXIMUM_LIMIT = 200;

	public AuditEventQuery {
		if (limit < 1 || limit > MAXIMUM_LIMIT) {
			throw new IllegalArgumentException("Audit event query limit must be between 1 and 200");
		}
	}

	public static AuditEventQuery firstPage() {
		return new AuditEventQuery(DEFAULT_LIMIT, null);
	}

}
