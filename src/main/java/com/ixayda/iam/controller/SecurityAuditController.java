package com.ixayda.iam.controller;

import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.SecurityAuditEntryResponse;
import com.ixayda.iam.dto.SecurityAuditPageResponse;
import com.ixayda.iam.dto.SecurityAuditSearchRequest;
import com.ixayda.iam.model.SecurityAuditEntry;
import com.ixayda.iam.model.SecurityAuditEvent;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.model.SecurityAuditPage;
import com.ixayda.iam.service.SecurityAudits;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityAuditController {

	private static final Set<String> PARAMETERS = Set.of("from", "until", "action", "outcome", "actor", "source",
			"targetUserId", "correlationId", "pageSize", "cursor");

	private final SecurityAudits audits;

	SecurityAuditController(SecurityAudits audits) { this.audits = audits; }

	@InitBinder("auditSearch")
	void auditBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "searchSecurityAudits", summary = "查询安全审计", description = "需要当前管理员资格及有效的密码和 TOTP 管理会话。按记录时间和 UUID 倒序分页；默认每页 20 条，范围 1 至 100。时间区间为 [from, until)，时间使用带时区的 ISO 8601 格式；动作和结果使用区分大小写的枚举原名，其余条件精确匹配。游标须与原筛选条件一起使用，可调整 pageSize；nextCursor 为 null 时结束。游标只是分页位置，不授予权限；分页不提供跨请求快照。拒绝重复、额外查询参数及请求体，不从请求头绑定业务字段。结果只包含事件归属及记录时间，不返回密码、凭据或因素秘密。")
	@ApiResponse(responseCode = "200", description = "安全审计分页结果", content = @Content(mediaType = "application/json", schema = @Schema(implementation = SecurityAuditPageResponse.class)))
	@ApiResponse(responseCode = "400", description = "查询条件、游标或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格或 MFA 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@GetMapping(path = "/api/admin/audits", produces = MediaType.APPLICATION_JSON_VALUE)
	public SecurityAuditPageResponse search(@ParameterObject @ModelAttribute("auditSearch") SecurityAuditSearchRequest query,
			HttpServletRequest request) {
		IdentityQueryRequests.require(request, PARAMETERS, "Invalid audit query");
		if ((request.getParameter("pageSize") != null && query.pageSize() == null)
				|| !matches(request, "action", query.action()) || !matches(request, "outcome", query.outcome())) {
			throw new IllegalArgumentException("Invalid audit query");
		}
		var filter = new SecurityAuditFilter(parseTime(query.from()), parseTime(query.until()), query.action(), query.outcome(),
				query.actor(), query.source(), parseId(query.targetUserId()), parseId(query.correlationId()));
		var page = this.audits.search(filter, query.pageSize() == null ? 20 : query.pageSize(), decodeCursor(query.cursor()));
		return new SecurityAuditPageResponse(page.items().stream().map(SecurityAuditController::response).toList(), encodeCursor(page.nextCursor()));
	}

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidAuditQuery() {
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid audit query");
	}

	private static boolean matches(HttpServletRequest request, String parameter, Enum<?> value) {
		return request.getParameter(parameter) == null || value != null && value.name().equals(request.getParameter(parameter));
	}

	private static SecurityAuditEntryResponse response(SecurityAuditEntry entry) {
		return new SecurityAuditEntryResponse(entry.id(), entry.action(), entry.outcome(), entry.targetUserId(),
				entry.context().actor(), entry.context().source(), entry.context().correlationId(), entry.recordedAt(),
				entry.target() == null ? null : entry.target().type().name(), entry.target() == null ? null : entry.target().id());
	}

	private static Instant parseTime(String value) {
		if (value == null) { return null; }
		try { return Instant.parse(value); }
		catch (DateTimeException ex) { throw new IllegalArgumentException("Invalid audit time", ex); }
	}

	private static UUID parseId(String value) {
		if (value == null) { return null; }
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) { throw new IllegalArgumentException("Invalid audit identifier"); }
		return id;
	}

	/** Encoded filters bind a position to its query; the cursor never authorizes access. */
	private static String encodeCursor(SecurityAuditPage.Cursor cursor) {
		if (cursor == null) { return null; }
		var filter = cursor.filter();
		String text = String.join("\n", "1", cursor.recordedAt().toString(), cursor.id().toString(), text(filter.fromInclusive()),
				text(filter.untilExclusive()), text(filter.action()), text(filter.outcome()), text(filter.actor()), text(filter.source()),
				text(filter.targetUserId()), text(filter.correlationId()));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
	}

	private static SecurityAuditPage.Cursor decodeCursor(String value) {
		if (value == null) { return null; }
		if (value.isEmpty() || value.length() > 1024) { throw new IllegalArgumentException("Invalid audit cursor"); }
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		String text = new String(bytes, StandardCharsets.UTF_8);
		String[] parts = text.split("\n", -1);
		if (parts.length != 11 || !parts[0].equals("1") || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
			throw new IllegalArgumentException("Invalid audit cursor");
		}
		var filter = new SecurityAuditFilter(parseTime(optional(parts[3])), parseTime(optional(parts[4])),
				parts[5].isEmpty() ? null : SecurityAuditEvent.Action.valueOf(parts[5]),
				parts[6].isEmpty() ? null : SecurityAuditEntry.Outcome.valueOf(parts[6]), optional(parts[7]), optional(parts[8]),
				parseId(optional(parts[9])), parseId(optional(parts[10])));
		return new SecurityAuditPage.Cursor(parseTime(parts[1]), parseId(parts[2]), filter);
	}

	private static String text(Object value) { return value == null ? "" : value.toString(); }
	private static String optional(String value) { return value.isEmpty() ? null : value; }

}
