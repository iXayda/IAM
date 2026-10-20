package com.ixayda.iam.controller;

import java.beans.PropertyEditorSupport;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityMfaRecoveryCodesResponse;
import com.ixayda.iam.dto.IdentityTotpRecoveryCompletionRequest;
import com.ixayda.iam.dto.IdentityTotpRecoveryRequest;
import com.ixayda.iam.dto.IdentityTotpRecoveryResponse;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityTotpRecoverySessions;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentityTotpRecoveryController {

	private final IdentityTotpRecoverySessions recoveries;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityTotpRecoveryController(IdentityTotpRecoverySessions recoveries) { this.recoveries = recoveries; }

	@InitBinder({ "totpRecovery", "totpRecoveryCompletion" })
	void recoveryBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
		binder.registerCustomEditor(UUID.class, new PropertyEditorSupport() {
			@Override public void setAsText(String text) {
				UUID id = UUID.fromString(text);
				if (!id.toString().equalsIgnoreCase(text)) { throw new IllegalArgumentException("Full UUID is required"); }
				setValue(id);
			}
		});
	}

	@Operation(operationId = "beginCurrentTotpRecovery", summary = "开始本人 TOTP 恢复", description = "需要本人有效密码会话和 CSRF，重新提交 currentPassword 及一个未使用的 recoveryCode，不要求旧认证器或管理员 MFA。用户身份由会话确定，已有会话或管理验证不能代替本次双凭据验证。密码和恢复码分别复用共享失败预算。成功消费恢复码，保留旧因素、其他旧恢复码和已有会话，一次性交付十分钟有效的恢复凭据及新认证器材料；重新开始须提交另一个未使用的恢复码，并使旧恢复凭据失效。恢复码在提交后不退还；开始响应交付失败也须用另一个恢复码重试。不会提升管理权限或延长密码认证绝对期限。凭据、密钥和 otpauth URI 不得进入 URL、日志或浏览器持久存储；由独立身份前端展示或生成二维码，没有重新读取秘密的接口。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "待确认恢复、新因素及秘密，仅本次交付", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityTotpRecoveryResponse.class)))
	@ApiResponse(responseCode = "400", description = "当前密码、活动因素或恢复码被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "密码或恢复码共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", headers = @Header(name = "Retry-After", description = "仅入口限流返回的重试等待秒数", schema = @Schema(type = "integer", minimum = "1")), content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpRecoveryRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/recovery", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> begin(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpRecovery") IdentityTotpRecoveryRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var session = request.getSession(false);
		var evidence = passwordSession(session);
		if (evidence == null) { return invalidSession(request, response); }
		var context = new MfaRecoveryCodeContext("browser:totp-recovery", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		IdentityTotpRecoverySessions.BeginResult result;
		try {
			result = this.recoveries.begin(userId, session.getId(), evidence.version(), evidence.authenticatedAt(),
					command.currentPassword(), command.recoveryCode(), context, () -> {
						try { response.flushBuffer(); }
						catch (IOException ex) { throw new UncheckedIOException(ex); }
					});
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		if (result.status() != IdentityTotpRecoverySessions.Status.COMPLETED) { return failure(result.status(), request, response); }
		var pending = result.recovery();
		var enrollment = pending.enrollment();
		return ResponseEntity.ok(new IdentityTotpRecoveryResponse(pending.recoveryId(), pending.token(), enrollment.factorId(),
				enrollment.secret(), enrollment.provisioningUri(), enrollment.expiresAt()));
	}

	@Operation(operationId = "completeCurrentTotpRecovery", summary = "完成本人 TOTP 恢复", description = "需要本人有效密码会话和 CSRF，提交 recoveryId、token 和新认证器的 code。恢复凭据与账号、原因素、恢复码批次、密码版本和十分钟期限绑定；同一账号的其他有效密码会话可携完整凭据完成，其他账号不能使用。完成与注册及其他 TOTP 入口共享失败预算。重新生成原因素恢复码或完成正常因素更换后，该恢复凭据失效；两个流程的凭据不能互换。成功原子激活新因素、消费确认码、废止旧因素和全部旧恢复码、递增认证版本、撤销本人全部 IAM 会话及应用授权并记录审计；清除当前 Cookie，不自动登录或授予管理权限。仅本次返回十个新恢复码，前端应提示离线保存并清理内存；不得进入 URL、日志或浏览器持久存储。事务失败保留完成前状态；提交后网络交付失败时恢复已生效，应正常登录并用新认证器的新验证码重新生成恢复码，不能重放恢复凭据找回。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "因素已恢复且全部本人会话及应用授权已撤销，新恢复码仅本次交付", headers = @Header(name = "Set-Cookie", description = "清除 __Host-IAMSESSION Cookie，Secure、HttpOnly、Path=/、SameSite=Lax", schema = @Schema(type = "string")), content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityMfaRecoveryCodesResponse.class)))
	@ApiResponse(responseCode = "400", description = "恢复凭据、因素或验证码被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "TOTP 共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", headers = @Header(name = "Retry-After", description = "仅入口限流返回的重试等待秒数", schema = @Schema(type = "integer", minimum = "1")), content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpRecoveryCompletionRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/recovery/complete", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> complete(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpRecoveryCompletion") IdentityTotpRecoveryCompletionRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var session = request.getSession(false);
		var evidence = passwordSession(session);
		if (evidence == null) { return invalidSession(request, response); }
		var context = new TotpAuthenticationContext("browser:totp-recovery", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		IdentityTotpRecoverySessions.CompletionResult result;
		try {
			result = this.recoveries.complete(userId, session.getId(), evidence.version(), evidence.authenticatedAt(),
					command.recoveryId(), command.token(), command.code(), context);
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		if (result.status() != IdentityTotpRecoverySessions.Status.COMPLETED) { return failure(result.status(), request, response); }
		// The transaction has committed revocation; invalidate the wrapper before its finalizer can save it.
		this.logout.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
		var issued = result.codeSet();
		return ResponseEntity.ok(new IdentityMfaRecoveryCodesResponse(issued.generationId(), issued.codes(), issued.issuedAt()));
	}

	private static PasswordSession passwordSession(HttpSession session) {
		return session != null && session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version
				&& session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt
				? new PasswordSession(version, authenticatedAt) : null;
	}

	private ResponseEntity<?> failure(IdentityTotpRecoverySessions.Status status, HttpServletRequest request, HttpServletResponse response) {
		return switch (status) {
			case INVALID_SESSION -> invalidSession(request, response);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("TOTP recovery rejected");
			case COMPLETED -> throw new IllegalStateException("Unexpected completed recovery");
		};
	}

	private ResponseEntity<?> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private record PasswordSession(long version, long authenticatedAt) { }

}
