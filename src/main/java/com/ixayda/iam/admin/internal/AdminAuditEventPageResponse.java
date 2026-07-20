package com.ixayda.iam.admin.internal;

import java.util.List;
import java.util.Objects;

record AdminAuditEventPageResponse(List<AdminAuditEventResponse> events, String nextCursor) {

	AdminAuditEventPageResponse {
		Objects.requireNonNull(events, "Admin audit events must not be null");
		events = List.copyOf(events);
	}

}
