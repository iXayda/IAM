package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityUserSetupManagementRequest;
import com.ixayda.iam.dto.IdentityUserSetupResponse;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserSetupManagement;

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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Tag(name = "account-setup", description = "受控账号开通凭据")
public class IdentityUserSetupController {

	private final IdentityUserSetupManagement setups;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityUserSetupController(IdentityUserSetupManagement setups, IdentityAdministratorSessions administrators) {
		this.setups = setups;
		this.administrators = administrators;
	}

	@InitBinder("setupManagement")
	void setupBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "issueUserSetup", summary = "签发开通凭据", description = "由组织工作人员先核验身份，再签发并通过已核验渠道人工交付。需要有效管理员 MFA 会话及本次操作的新 TOTP。userId 使用完整 UUID；仅接受 code 及 CSRF，拒绝查询参数、重复及额外字段。只允许尚无密码的待开通账号，有效期为 30 分钟；重新签发立即替换旧凭据。事务提交后仅本次响应返回原文，不能查询找回；交付失败或结果不确定时取消或重新签发。不设置密码、不激活用户、不延长认证期限。原文不得进入 URL、日志或浏览器本地存储。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "凭据已提交，仅本次交付原文", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityUserSetupResponse.class)))
	@ApiResponse(responseCode = "400", description = "用户标识、TOTP 或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "用户不存在；仅在本次 TOTP 验证成功后返回", content = @Content)
	@ApiResponse(responseCode = "409", description = "账号不是待开通状态或已经有密码", content = @Content)
	@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityUserSetupManagementRequest.class)))
	@PostMapping(path = "/api/admin/users/{userId}/setup", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> issue(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId,
			@Parameter(hidden = true) @ModelAttribute("setupManagement") IdentityUserSetupManagementRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return manage(actorId, parseUserId(userId), IdentityUserSetupManagement.Operation.ISSUE, command.code(), request, response);
	}

	@Operation(operationId = "cancelUserSetup", summary = "取消开通凭据", description = "需要有效管理员 MFA 会话及本次操作的新 TOTP。userId 使用完整 UUID；仅接受 code 及 CSRF，拒绝查询参数、重复及额外字段。取消该用户尚未消费的开通凭据，包括已过期凭据；允许为禁用账号取消。没有待取消凭据时也返回 204，不重复记录取消事件；每次验证成功均消费 TOTP。不改变用户状态、密码或会话，不延长认证期限。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "凭据已取消或没有待取消凭据", content = @Content)
	@ApiResponse(responseCode = "400", description = "用户标识、TOTP 或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "用户不存在；仅在本次 TOTP 验证成功后返回", content = @Content)
	@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityUserSetupManagementRequest.class)))
	@PostMapping(path = "/api/admin/users/{userId}/setup/cancel", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<?> cancel(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId,
			@Parameter(hidden = true) @ModelAttribute("setupManagement") IdentityUserSetupManagementRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return manage(actorId, parseUserId(userId), IdentityUserSetupManagement.Operation.CANCEL, command.code(), request, response);
	}

	private ResponseEntity<?> manage(UUID actorId, UUID targetId, IdentityUserSetupManagement.Operation operation, String code,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID correlationId = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlationId, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var management = stored instanceof IdentityAdministratorAuthentication evidence ? evidence : null;
		String source = operation == IdentityUserSetupManagement.Operation.ISSUE ? "browser:admin-setup-issue" : "browser:admin-setup-cancel";
		var context = new TotpAuthenticationContext(source, InetAddress.getByName(request.getRemoteAddr()), correlationId);
		IdentityUserSetupManagement.Result result;
		try {
			result = this.setups.manage(actorId, session.getId(), version, authenticatedAt, management, targetId, operation, code, context, () -> {
				try { response.flushBuffer(); }
				catch (IOException ex) { throw new UncheckedIOException(ex); }
			});
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		return switch (result.status()) {
			case ISSUED -> ResponseEntity.ok(new IdentityUserSetupResponse(result.setup().userId(), result.setup().token(), result.setup().expiresAt()));
			case CANCELLED -> ResponseEntity.noContent().build();
			case INVALID_SESSION -> invalidSession(actorId, correlationId, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case CONFLICT -> ResponseEntity.status(409).build();
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Account setup management rejected");
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(actorId, correlationId);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidSetupRequest() {
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid account setup request");
	}

	private static UUID parseUserId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) { throw new IllegalArgumentException("Invalid user id"); }
		return id;
	}

}
