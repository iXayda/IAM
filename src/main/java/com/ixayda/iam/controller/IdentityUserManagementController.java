package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityUserCreateRequest;
import com.ixayda.iam.dto.IdentityUserPageResponse;
import com.ixayda.iam.dto.IdentityUserResponse;
import com.ixayda.iam.dto.IdentityUserSearchRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserPage;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserCreations;
import com.ixayda.iam.service.IdentityUsers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
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
public class IdentityUserManagementController {

	private final IdentityUsers users;
	private final IdentityUserCreations creations;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityUserManagementController(IdentityUsers users, IdentityUserCreations creations, IdentityAdministratorSessions administrators) {
		this.users = users;
		this.creations = creations;
		this.administrators = administrators;
	}

	@InitBinder({ "userSearch", "userCreation" })
	void userBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "searchUsers", summary = "搜索用户", description = "需要当前管理员资格及有效的密码和 TOTP 管理会话。仅接受 keyword、status、pageSize、cursor 查询参数；默认每页 20 条，范围 1 至 100。游标须与原关键词和状态一起使用；按创建时间和 UUID 稳定排序，返回 nextCursor 为 null 时结束。拒绝重复参数、额外参数及请求体。")
	@ApiResponse(responseCode = "200", description = "用户分页结果")
	@ApiResponse(responseCode = "400", description = "查询条件、游标或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格或 MFA 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@GetMapping(path = "/api/admin/users", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityUserPageResponse search(@org.springdoc.core.annotations.ParameterObject @ModelAttribute("userSearch") IdentityUserSearchRequest query, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of("keyword", "status", "pageSize", "cursor"), "Invalid user query");
		if ((request.getParameter("pageSize") != null && query.pageSize() == null)
				|| (request.getParameter("status") != null
						&& (query.status() == null || !query.status().name().equals(request.getParameter("status"))))) {
			throw new IllegalArgumentException("Invalid user query");
		}
		var page = this.users.search(query.keyword(), query.status(), query.pageSize() == null ? 20 : query.pageSize(), decodeCursor(query.cursor()));
		return new IdentityUserPageResponse(page.items().stream().map(IdentityUserManagementController::response).toList(), encodeCursor(page.nextCursor()));
	}

	@Operation(operationId = "getUser", summary = "查询指定用户", description = "需要有效的管理员 MFA 会话。userId 使用完整 UUID；不接受请求体及查询参数。仅返回身份资料，不返回凭据、恢复凭据、因素秘密或会话内容。")
	@ApiResponse(responseCode = "200", description = "用户身份资料")
	@ApiResponse(responseCode = "400", description = "用户标识或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格或 MFA 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "用户不存在", content = @Content)
	@GetMapping(path = "/api/admin/users/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<IdentityUserResponse> find(@PathVariable String userId, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of(), "Invalid user query");
		return this.users.findById(parseUserId(userId)).map(IdentityUserManagementController::response)
				.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
	}

	@Operation(operationId = "createUser", summary = "创建待开通用户", description = "需要有效的管理员 MFA 会话，并重新验证本次操作的新 TOTP。仅接受 username、displayName、code 及 CSRF；拒绝查询参数、重复及额外字段。创建 PENDING 用户，不设置密码、不签发开通凭据、不延长管理期限。账号名称统一为小写。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "201", description = "用户已创建，Location 指向详情地址",
			content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityUserResponse.class)))
	@ApiResponse(responseCode = "400", description = "输入或 TOTP 被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "409", description = "账号名已被使用", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "429", description = "TOTP 验证受限，或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityUserCreateRequest.class)))
	@PostMapping(path = "/api/admin/users", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> create(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId,
			@Parameter(hidden = true) @ModelAttribute("userCreation") IdentityUserCreateRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID correlationId = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlationId, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var management = stored instanceof IdentityAdministratorAuthentication evidence ? evidence : null;
		var context = new TotpAuthenticationContext("browser:admin-user-create", InetAddress.getByName(request.getRemoteAddr()), correlationId);
		IdentityUserCreations.Result result;
		try {
			result = this.creations.create(actorId, session.getId(), version, authenticatedAt, management,
					command.username(), command.displayName(), command.code(), context, () -> {
						try { response.flushBuffer(); }
						catch (IOException ex) { throw new UncheckedIOException(ex); }
					});
		}
		catch (RuntimeException ex) {
			// A delayed commit may fail after the mutable session was saved inside the workflow.
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		return switch (result.status()) {
			case CREATED -> ResponseEntity.created(URI.create(request.getContextPath() + "/api/admin/users/" + result.user().id()))
					.body(response(result.user()));
			case INVALID_SESSION -> invalidSession(actorId, correlationId, request, response);
			case FORBIDDEN -> ResponseEntity.status(403).build();
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case CONFLICT -> ResponseEntity.status(409).contentType(MediaType.TEXT_PLAIN).body("Username unavailable");
			case INVALID_INPUT, REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("User creation rejected");
		};
	}

	private ResponseEntity<Void> invalidSession(UUID actorId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(actorId, correlationId);
		return ResponseEntity.status(401).build();
	}

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidUserRequest() {
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid user request");
	}

	private static IdentityUserResponse response(IdentityUser user) {
		return new IdentityUserResponse(user.id(), user.username(), user.displayName(), user.status(), user.createdAt());
	}

	private static UUID parseUserId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) {
			throw new IllegalArgumentException("Invalid user id");
		}
		return id;
	}

	/** A cursor is a transport position, never authentication or permission to query users. */
	private static String encodeCursor(IdentityUserPage.Cursor cursor) {
		if (cursor == null) { return null; }
		String text = cursor.createdAt() + "\n" + cursor.id() + "\n" + (cursor.status() == null ? "" : cursor.status().name()) + "\n" + cursor.keyword();
		return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
	}

	private static IdentityUserPage.Cursor decodeCursor(String value) {
		if (value == null) { return null; }
		if (value.isEmpty() || value.length() > 1024) { throw new IllegalArgumentException("Invalid user cursor"); }
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		String text = new String(bytes, StandardCharsets.UTF_8);
		String[] parts = text.split("\n", -1);
		if (parts.length != 4 || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
			throw new IllegalArgumentException("Invalid user cursor");
		}
		try {
			Instant createdAt = Instant.parse(parts[0]);
			// PostgreSQL timestamps are finite and use microsecond resolution, as do issued cursors.
			if (createdAt.isBefore(Instant.parse("-4712-01-01T00:00:00Z")) || !createdAt.isBefore(Instant.parse("+294277-01-01T00:00:00Z"))
					|| createdAt.getNano() % 1000 != 0) {
				throw new IllegalArgumentException("Invalid user cursor");
			}
			return new IdentityUserPage.Cursor(createdAt, parseUserId(parts[1]), parts[3], parts[2].isEmpty() ? null : IdentityUser.Status.valueOf(parts[2]));
		}
		catch (DateTimeException ex) { throw new IllegalArgumentException("Invalid user cursor", ex); }
	}

}
