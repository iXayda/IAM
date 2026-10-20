package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityPasswordRecoveryCompletionRequest;
import com.ixayda.iam.dto.IdentityPasswordRecoveryManagementRequest;
import com.ixayda.iam.dto.IdentityPasswordRecoveryResponse;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.PasswordRecoveryContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityPasswordRecoveryCompletions;
import com.ixayda.iam.service.IdentityPasswordRecoveryManagement;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.session.web.http.CookieSerializer;
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
@Tag(name = "password-recovery", description = "受控密码恢复凭据")
public class IdentityPasswordRecoveryController {

	private final IdentityPasswordRecoveryManagement recoveries;
	private final IdentityAdministratorSessions administrators;
	private final IdentityPasswordRecoveryCompletions completions;
	private final CookieSerializer cookies;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityPasswordRecoveryController(IdentityPasswordRecoveryManagement recoveries, IdentityAdministratorSessions administrators,
			IdentityPasswordRecoveryCompletions completions, CookieSerializer cookies) {
		this.recoveries = recoveries;
		this.administrators = administrators;
		this.completions = completions;
		this.cookies = cookies;
	}

	@InitBinder({ "recoveryManagement", "recoveryCompletion" })
	void recoveryBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@SecurityRequirements
	@Operation(operationId = "completePasswordRecovery", summary = "完成密码恢复", description = "无需登录。先从 /api/csrf 获取所属会话 Cookie 和 CSRF 令牌，通过同源 HTTPS 提交 userId、token、newPassword 及 CSRF；拒绝查询参数、重复和额外字段。userId 为完整 UUID，凭据原样提交，不得进入 URL、日志或本地存储。账号和来源分别限制每 15 分钟 5 次及 30 次失败；未知或无效账号、错绑、过期、取消、被替换和重放的凭据统一返回无效凭据。仅在凭据有效时检查密码规则，不合规可在剩余有效期及预算内重试。成功原子替换密码、递增版本、消费凭据、撤销目标全部 IAM 会话及应用授权并记录审计；拒绝与当前密码相同的密码（按 NFC 匹配）。不自动登录，不改变用户状态、管理资格或 MFA；之后通过 /login 正常登录。恢复本人时清除当前会话 Cookie，恢复其他账号时保留调用者身份。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "密码已替换且全部所属会话已撤销，仍需正常登录", content = @Content,
			headers = @Header(name = "Set-Cookie", description = "恢复本人时清除 __Host-IAMSESSION Cookie：Secure、HttpOnly、Path=/、SameSite=Lax；匿名或恢复其他账号时不清调用者 Cookie", schema = @Schema(type = "string")))
	@ApiResponse(responseCode = "400", description = "无效凭据返回 Invalid password recovery credential；有效凭据的密码不合规则返回 Password does not meet policy；请求边界拒绝使用 JSON 错误", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 令牌缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "恢复失败预算耗尽，或公共入口限流；只有公共入口限流提供 Retry-After",
			headers = @Header(name = "Retry-After", description = "仅公共入口限流提供，表示等待秒数", schema = @Schema(type = "integer", minimum = "1")), content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityPasswordRecoveryCompletionRequest.class)))
	@PostMapping(path = "/api/password-recovery/complete", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<String> complete(@Parameter(hidden = true) @AuthenticationPrincipal UUID callerId, @Parameter(hidden = true) @ModelAttribute("recoveryCompletion") IdentityPasswordRecoveryCompletionRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var context = new PasswordRecoveryContext("browser:password-recovery", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		// Persist before taking the target lock. An unchanged session will not be saved again after revocation.
		// The outer response buffer prevents this Spring Session flush from publishing an HTTP response.
		response.flushBuffer();
		return switch (this.completions.complete(command.userId(), command.token(), command.newPassword(), context)) {
			case COMPLETED -> {
				if (callerId != null && callerId.toString().equalsIgnoreCase(command.userId())) {
					// Database revocation already committed. Do not invalidate/save this revoked session again.
					SecurityContextHolder.clearContext();
					var cookie = new CookieSerializer.CookieValue(request, response, "");
					cookie.setCookieMaxAge(0);
					this.cookies.writeCookieValue(cookie);
				}
				yield ResponseEntity.noContent().build();
			}
			case INVALID_PROOF -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid password recovery credential");
			case INVALID_PASSWORD -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Password does not meet policy");
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Password recovery temporarily unavailable");
		};
	}

	@Operation(operationId = "issuePasswordRecovery", summary = "签发密码恢复凭据", description = "由组织工作人员先核验身份，再签发并通过已核验渠道人工交付。需要有效管理员 MFA 会话及本次操作的新 TOTP。userId 使用完整 UUID；仅接受 code 及 CSRF，拒绝查询参数、重复及额外字段。只允许已有密码的活动账号；凭据绑定签发时的密码版本，有效期为 30 分钟；重新签发立即替换旧凭据。事务提交后仅本次响应返回原文，不能查询找回；交付失败或结果不确定时取消或重新签发。不修改密码或撤销会话，不改变用户状态，不延长认证期限；不代替管理员 MFA 或因素恢复。原文不得进入 URL、日志或浏览器本地存储。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "凭据已提交，仅本次交付原文", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityPasswordRecoveryResponse.class)))
	@ApiResponse(responseCode = "400", description = "用户标识、TOTP 或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "用户不存在；仅在本次 TOTP 验证成功后返回", content = @Content)
	@ApiResponse(responseCode = "409", description = "账号不是活动状态或尚无密码", content = @Content)
	@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityPasswordRecoveryManagementRequest.class)))
	@PostMapping(path = "/api/admin/users/{userId}/password-recovery", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> issue(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId,
			@Parameter(hidden = true) @ModelAttribute("recoveryManagement") IdentityPasswordRecoveryManagementRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return manage(actorId, parseUserId(userId), IdentityPasswordRecoveryManagement.Operation.ISSUE, command.code(), request, response);
	}

	@Operation(operationId = "cancelPasswordRecovery", summary = "取消密码恢复凭据", description = "需要有效管理员 MFA 会话及本次操作的新 TOTP。userId 使用完整 UUID；仅接受 code 及 CSRF，拒绝查询参数、重复及额外字段。取消该用户尚未消费的密码恢复凭据，包括已过期凭据；允许为禁用账号取消。没有待取消凭据时也返回 204，不重复记录取消事件；每次验证成功均消费 TOTP。不改变用户状态、密码或会话，不延长认证期限。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "凭据已取消或没有待取消凭据", content = @Content)
	@ApiResponse(responseCode = "400", description = "用户标识、TOTP 或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "用户不存在；仅在本次 TOTP 验证成功后返回", content = @Content)
	@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityPasswordRecoveryManagementRequest.class)))
	@PostMapping(path = "/api/admin/users/{userId}/password-recovery/cancel", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<?> cancel(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId,
			@Parameter(hidden = true) @ModelAttribute("recoveryManagement") IdentityPasswordRecoveryManagementRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return manage(actorId, parseUserId(userId), IdentityPasswordRecoveryManagement.Operation.CANCEL, command.code(), request, response);
	}

	private ResponseEntity<?> manage(UUID actorId, UUID targetId, IdentityPasswordRecoveryManagement.Operation operation, String code,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID correlationId = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlationId, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var management = stored instanceof IdentityAdministratorAuthentication evidence ? evidence : null;
		String source = operation == IdentityPasswordRecoveryManagement.Operation.ISSUE ? "browser:admin-password-recovery-issue" : "browser:admin-password-recovery-cancel";
		var context = new TotpAuthenticationContext(source, InetAddress.getByName(request.getRemoteAddr()), correlationId);
		IdentityPasswordRecoveryManagement.Result result;
		try {
			result = this.recoveries.manage(actorId, session.getId(), version, authenticatedAt, management, targetId, operation, code, context, () -> {
				try { response.flushBuffer(); }
				catch (IOException ex) { throw new UncheckedIOException(ex); }
			});
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		return switch (result.status()) {
			case ISSUED -> ResponseEntity.ok(new IdentityPasswordRecoveryResponse(result.recovery().userId(), result.recovery().token(), result.recovery().expiresAt()));
			case CANCELLED -> ResponseEntity.noContent().build();
			case INVALID_SESSION -> invalidSession(actorId, correlationId, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case CONFLICT -> ResponseEntity.status(409).build();
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Password recovery management rejected");
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(actorId, correlationId);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidRecoveryRequest() {
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid password recovery request");
	}

	private static UUID parseUserId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) { throw new IllegalArgumentException("Invalid user id"); }
		return id;
	}

}
