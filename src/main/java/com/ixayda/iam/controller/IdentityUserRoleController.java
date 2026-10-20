package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityUserRoleChangeRequest;
import com.ixayda.iam.dto.IdentityUserRoleChangeResponse;
import com.ixayda.iam.dto.IdentityUserRolePageResponse;
import com.ixayda.iam.dto.IdentityUserRoleResponse;
import com.ixayda.iam.dto.IdentityUserRoleSearchRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityUserRolePage;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserRoleManagement;
import com.ixayda.iam.service.IdentityUserRoles;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Tag(name = "user-roles", description = "需要当前管理员资格和有效的密码及 TOTP 管理会话。写操作携带本次新 TOTP。绑定配置不直接代表有效应用权限，也不授予 IAM 管理资格。")
@ApiResponse(responseCode = "400", description = "输入、TOTP 或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "404", description = "用户、资源或角色不存在", content = @Content)
@ApiResponse(responseCode = "409", description = "绑定版本变化或当前状态不允许授予", content = @Content(mediaType = "text/plain"))
@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
public class IdentityUserRoleController {

	private final IdentityUserRoles bindings;
	private final IdentityUserRoleManagement management;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityUserRoleController(IdentityUserRoles bindings, IdentityUserRoleManagement management, IdentityAdministratorSessions administrators) {
		this.bindings = bindings;
		this.management = management;
		this.administrators = administrators;
	}

	@InitBinder({ "userRoleSearch", "userRoleChange" })
	void userRoleBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "searchUserRoles", summary = "查询用户在指定资源的角色绑定", description = "仅接受 pageSize 和 cursor，不接受请求体或重复字段。每页 1 至 100 条，默认 20，按绑定创建时间和角色 UUID 升序。包括禁用主体的保留绑定。返回同一语句快照的 version；nextCursor 为 null 时结束，绑定变化返回 409，须从第一页重读。")
	@GetMapping(path = "/api/admin/users/{userId}/resources/{resourceId}/roles", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityUserRolePageResponse search(@PathVariable String userId, @PathVariable String resourceId,
			@org.springdoc.core.annotations.ParameterObject @ModelAttribute("userRoleSearch") IdentityUserRoleSearchRequest query,
			HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of("pageSize", "cursor"), "Invalid binding query");
		if (request.getParameter("pageSize") != null && (query.pageSize() == null || !query.pageSize().toString().equals(request.getParameter("pageSize")))) {
			throw new IllegalArgumentException("Invalid binding query");
		}
		var page = this.bindings.search(parseId(userId), parseId(resourceId), query.pageSize() == null ? 20 : query.pageSize(), decodeCursor(query.cursor()));
		return new IdentityUserRolePageResponse(page.items().stream().map(binding -> new IdentityUserRoleResponse(
				binding.userId(), binding.resourceId(), binding.roleId(), binding.createdAt())).toList(), page.version(), encodeCursor(page.nextCursor()));
	}

	@Operation(operationId = "grantUserRole", summary = "授予用户资源角色", description = "携带该用户在角色所属资源的绑定 version 与本次操作的新 TOTP code。未变更过的绑定版本为 0。待开通用户可预配置；禁用用户、资源或角色拒绝授予。实际授予撤销该用户在该资源的全部旧应用授权。无变化操作仍验证和消费 TOTP，保持绑定版本和变更审计不变。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也接受 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "返回绑定变更结果及当前绑定版本", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityUserRoleChangeResponse.class)))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityUserRoleChangeRequest.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/users/{userId}/roles/{roleId}/grant", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> grant(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId, @PathVariable String roleId,
			@Parameter(hidden = true) @ModelAttribute("userRoleChange") IdentityUserRoleChangeRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return change(actorId, parseId(userId), parseId(roleId), command, true, request, response);
	}

	@Operation(operationId = "revokeUserRole", summary = "撤销用户资源角色", description = "携带该用户在角色所属资源的绑定 version 与本次操作的新 TOTP code。禁用主体仍可撤销；实际撤销同时终止该用户在该资源的全部应用授权；撤销最后一个角色后版本仍保留。无变化操作仍消费 TOTP；目标缺失或版本冲突回滚本次 TOTP 消费。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也接受 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "返回绑定变更结果及当前绑定版本", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityUserRoleChangeResponse.class)))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityUserRoleChangeRequest.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/users/{userId}/roles/{roleId}/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> revoke(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId, @PathVariable String roleId,
			@Parameter(hidden = true) @ModelAttribute("userRoleChange") IdentityUserRoleChangeRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return change(actorId, parseId(userId), parseId(roleId), command, false, request, response);
	}

	private ResponseEntity<?> change(UUID actorId, UUID userId, UUID roleId, IdentityUserRoleChangeRequest command, boolean grant,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (command.version() == null || !command.version().toString().equals(request.getParameter("version"))) {
			throw new IllegalArgumentException("Binding version is required");
		}
		UUID correlation = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlation, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var evidence = stored instanceof IdentityAdministratorAuthentication current ? current : null;
		var context = new IdentityAdministratorContext(actorId, session.getId(), version, authenticatedAt, evidence,
				new TotpAuthenticationContext(grant ? "browser:admin-user-role-grant" : "browser:admin-user-role-revoke",
						InetAddress.getByName(request.getRemoteAddr()), correlation));
		IdentityUserRoleManagement.Result result;
		try { result = this.management.change(context, userId, roleId, command.version(), grant, command.code(), save(response)); }
		catch (RuntimeException ex) { session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true); throw ex; }
		return switch (result.status()) {
			case COMPLETED -> ResponseEntity.ok(new IdentityUserRoleChangeResponse(userId, result.change().resourceId(), roleId,
					result.change().changed(), result.change().version()));
			case INVALID_SESSION -> invalidSession(actorId, correlation, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case CONFLICT -> conflict();
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case INVALID_INPUT, REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("User role operation rejected");
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(actorId, correlationId);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private static Runnable save(HttpServletResponse response) {
		return () -> { try { response.flushBuffer(); } catch (IOException ex) { throw new UncheckedIOException(ex); } };
	}

	@ExceptionHandler(NoSuchElementException.class)
	ResponseEntity<Void> missingTarget() { return ResponseEntity.notFound().build(); }

	@ExceptionHandler(OptimisticLockingFailureException.class)
	ResponseEntity<String> conflict() { return ResponseEntity.status(409).contentType(MediaType.TEXT_PLAIN).body("User role conflict"); }

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidUserRoleRequest() { return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid user role request"); }

	private static UUID parseId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) { throw new IllegalArgumentException("Invalid identity"); }
		return id;
	}

	private static String encodeCursor(IdentityUserRolePage.Cursor cursor) {
		if (cursor == null) { return null; }
		String value = "1\n" + cursor.userId() + "\n" + cursor.resourceId() + "\n" + cursor.version() + "\n" + cursor.createdAt() + "\n" + cursor.roleId();
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
	}

	private static IdentityUserRolePage.Cursor decodeCursor(String value) {
		if (value == null) { return null; }
		if (value.isEmpty() || value.length() > 512) { throw new IllegalArgumentException("Invalid binding cursor"); }
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		String text = new String(bytes, StandardCharsets.UTF_8);
		String[] parts = text.split("\n", -1);
		if (parts.length != 6 || !parts[0].equals("1") || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
			throw new IllegalArgumentException("Invalid binding cursor");
		}
		try {
			long version = Long.parseLong(parts[3]);
			if (!Long.toString(version).equals(parts[3])) { throw new IllegalArgumentException("Invalid binding cursor"); }
			return new IdentityUserRolePage.Cursor(parseId(parts[1]), parseId(parts[2]), version, Instant.parse(parts[4]), parseId(parts[5]));
		}
		catch (DateTimeException ex) { throw new IllegalArgumentException("Invalid binding cursor", ex); }
	}

}
