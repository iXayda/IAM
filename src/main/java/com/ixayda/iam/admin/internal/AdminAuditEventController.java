package com.ixayda.iam.admin.internal;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.audit.AuditEventId;
import com.ixayda.iam.audit.AuditEventExportPage;
import com.ixayda.iam.audit.AuditEventExportQuery;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventPage;
import com.ixayda.iam.audit.AuditEventQuery;
import com.ixayda.iam.audit.InvalidAuditEventExportCursorException;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@RestController
final class AdminAuditEventController {

	static final String NDJSON_MEDIA_TYPE = MediaType.APPLICATION_NDJSON_VALUE;

	static final String NEXT_CURSOR_HEADER = "X-Audit-Next-Cursor";

	static final String EXPORT_METRIC = "iam.audit.export";

	private final AuditEventOperations events;

	private final ObjectMapper objectMapper;

	private final Counter successfulExports;

	private final Counter failedExports;

	AdminAuditEventController(AuditEventOperations events, ObjectMapper objectMapper, MeterRegistry meterRegistry) {
		this.events = events;
		this.objectMapper = objectMapper;
		this.successfulExports = exportCounter(meterRegistry, "success");
		this.failedExports = exportCounter(meterRegistry, "failure");
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

	@GetMapping(value = AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH, produces = NDJSON_MEDIA_TYPE)
	ResponseEntity<byte[]> export(@AuthenticationPrincipal AuthorizationPrincipal principal,
			@RequestParam Instant from, @RequestParam Instant to,
			@RequestParam(defaultValue = "1000") int limit, @RequestParam(required = false) UUID after) {
		AuditEventExportQuery query;
		try {
			query = new AuditEventExportQuery(from, to, limit,
					after == null ? null : new AuditEventId(after));
		}
		catch (IllegalArgumentException exception) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
		}
		try {
			AuditEventExportPage page = this.events.export(principal.tenantId(), query);
			byte[] body = encode(page);
			ResponseEntity.BodyBuilder response = ResponseEntity.ok()
				.cacheControl(CacheControl.noStore())
				.contentType(MediaType.parseMediaType(NDJSON_MEDIA_TYPE));
			page.next().ifPresent(cursor -> response.header(NEXT_CURSOR_HEADER, cursor.toString()));
			this.successfulExports.increment();
			return response.body(body);
		}
		catch (InvalidAuditEventExportCursorException exception) {
			this.failedExports.increment();
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
		}
		catch (RuntimeException exception) {
			this.failedExports.increment();
			throw exception;
		}
	}

	private byte[] encode(AuditEventExportPage page) {
		ByteArrayOutputStream body = new ByteArrayOutputStream();
		try {
			page.events().stream().map(AdminAuditEventResponse::from).forEach(event -> {
				body.writeBytes(this.objectMapper.writeValueAsBytes(event));
				body.write('\n');
			});
		}
		catch (JacksonException exception) {
			throw new IllegalStateException("Unable to encode audit export", exception);
		}
		return body.toByteArray();
	}

	private static Counter exportCounter(MeterRegistry meterRegistry, String outcome) {
		return Counter.builder(EXPORT_METRIC)
			.description("Audit export response generation outcomes")
			.tag("outcome", outcome)
			.register(meterRegistry);
	}

}
