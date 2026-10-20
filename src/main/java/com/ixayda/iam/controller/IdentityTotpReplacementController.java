package com.ixayda.iam.controller;

import java.beans.PropertyEditorSupport;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityMfaRecoveryCodesResponse;
import com.ixayda.iam.dto.IdentityTotpReplacementCompletionRequest;
import com.ixayda.iam.dto.IdentityTotpReplacementRequest;
import com.ixayda.iam.dto.IdentityTotpReplacementResponse;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityTotpReplacementSessions;

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
public class IdentityTotpReplacementController {

	private final IdentityTotpReplacementSessions replacements;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityTotpReplacementController(IdentityTotpReplacementSessions replacements) { this.replacements = replacements; }

	@InitBinder({ "totpReplacement", "totpReplacementCompletion" })
	void replacementBinding(ExtendedServletRequestDataBinder binder) {
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

	@Operation(operationId = "beginCurrentTotpReplacement", summary = "开始本人 TOTP 更换", description = "需要本人有效密码会话和 CSRF，重新提交 currentPassword 及旧认证器的新 code。用户身份由会话确定，不能仅凭会话或已有管理验证更换因素。密码和 TOTP 分别复用共享失败预算。成功消费旧验证码，保留旧因素、旧恢复码和已有会话，一次性交付十分钟有效的更换凭据及新认证器材料；重复开始须重新校验密码并提交新的旧因素验证码，并使旧更换凭据失效。不会提升管理权限或延长密码认证绝对期限。凭据、密钥和 otpauth URI 不得进入 URL、日志或浏览器持久存储；由独立身份前端展示或生成二维码。交付失败可用新的旧因素验证码重新开始，没有重新读取秘密的接口。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "待确认更换、新因素及秘密，仅本次交付", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityTotpReplacementResponse.class)))
	@ApiResponse(responseCode = "400", description = "当前密码、旧因素或验证码被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "密码或 TOTP 共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", headers = @Header(name = "Retry-After", description = "仅入口限流返回的重试等待秒数", schema = @Schema(type = "integer", minimum = "1")), content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpReplacementRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/replacement", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> begin(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpReplacement") IdentityTotpReplacementRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var session = request.getSession(false);
		var evidence = passwordSession(session);
		if (evidence == null) { return invalidSession(request, response); }
		var context = new TotpAuthenticationContext("browser:totp-replacement", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		IdentityTotpReplacementSessions.BeginResult result;
		try {
			result = this.replacements.begin(userId, session.getId(), evidence.version(), evidence.authenticatedAt(),
					command.currentPassword(), command.code(), context, () -> {
						try { response.flushBuffer(); }
						catch (IOException ex) { throw new UncheckedIOException(ex); }
					});
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		if (result.status() != IdentityTotpReplacementSessions.Status.COMPLETED) { return failure(result.status(), request, response); }
		var pending = result.replacement();
		var enrollment = pending.enrollment();
		return ResponseEntity.ok(new IdentityTotpReplacementResponse(pending.replacementId(), pending.token(), enrollment.factorId(),
				enrollment.secret(), enrollment.provisioningUri(), enrollment.expiresAt()));
	}

	@Operation(operationId = "completeCurrentTotpReplacement", summary = "完成本人 TOTP 更换", description = "需要本人有效密码会话和 CSRF，提交 replacementId、token 和新认证器的 code。凭据与账号、原因素、密码版本和十分钟期限绑定，与注册及其他 TOTP 入口共享失败预算。成功原子激活新因素、消费确认码、废止旧因素和全部旧恢复码、递增认证版本、撤销本人全部 IAM 会话及应用授权并记录审计；清除当前 Cookie，不自动登录或授予管理权限。仅本次返回十个新恢复码，前端应提示离线保存并清理内存；不得进入 URL、日志或浏览器持久存储。事务失败保留原状态；提交后网络交付失败时更换已生效，应正常登录并用新认证器的新验证码重新生成恢复码，不能重放更换凭据找回。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "因素已更换且全部本人会话及应用授权已撤销，新恢复码仅本次交付", headers = @Header(name = "Set-Cookie", description = "清除 __Host-IAMSESSION Cookie，Secure、HttpOnly、Path=/、SameSite=Lax", schema = @Schema(type = "string")), content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityMfaRecoveryCodesResponse.class)))
	@ApiResponse(responseCode = "400", description = "更换凭据、因素或验证码被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "TOTP 共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", headers = @Header(name = "Retry-After", description = "仅入口限流返回的重试等待秒数", schema = @Schema(type = "integer", minimum = "1")), content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpReplacementCompletionRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/replacement/complete", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> complete(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpReplacementCompletion") IdentityTotpReplacementCompletionRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var session = request.getSession(false);
		var evidence = passwordSession(session);
		if (evidence == null) { return invalidSession(request, response); }
		var context = new TotpAuthenticationContext("browser:totp-replacement", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		IdentityTotpReplacementSessions.CompletionResult result;
		try {
			result = this.replacements.complete(userId, session.getId(), evidence.version(), evidence.authenticatedAt(),
					command.replacementId(), command.token(), command.code(), context);
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		if (result.status() != IdentityTotpReplacementSessions.Status.COMPLETED) { return failure(result.status(), request, response); }
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

	private ResponseEntity<?> failure(IdentityTotpReplacementSessions.Status status, HttpServletRequest request, HttpServletResponse response) {
		return switch (status) {
			case INVALID_SESSION -> invalidSession(request, response);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("TOTP replacement rejected");
			case COMPLETED -> throw new IllegalStateException("Unexpected completed replacement");
		};
	}

	private ResponseEntity<?> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private record PasswordSession(long version, long authenticatedAt) { }

}
