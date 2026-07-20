package com.ixayda.iam.admin.internal;

import java.util.UUID;

import com.ixayda.iam.audit.AuditEventId;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventPage;
import com.ixayda.iam.audit.AuditEventQuery;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class AdminAuditEventController {

	private final AuditEventOperations events;

	AdminAuditEventController(AuditEventOperations events) {
		this.events = events;
	}

	@GetMapping(value = AdminWebSecurityConfiguration.AUDIT_EVENTS_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<AdminAuditEventPageResponse> events(@AuthenticationPrincipal AuthorizationPrincipal principal,
			@RequestParam(defaultValue = "50") int limit, @RequestParam(required = false) UUID before) {
		if (limit < 1 || limit > AuditEventQuery.MAXIMUM_LIMIT) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Audit event limit must be between 1 and 200");
		}
		AuditEventPage page = this.events.find(principal.tenantId(),
				new AuditEventQuery(limit, before == null ? null : new AuditEventId(before)));
		AdminAuditEventPageResponse response = new AdminAuditEventPageResponse(page.events()
			.stream()
			.map(AdminAuditEventResponse::from)
			.toList(), page.next().map(AuditEventId::toString).orElse(null));
		return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(response);
	}

}
