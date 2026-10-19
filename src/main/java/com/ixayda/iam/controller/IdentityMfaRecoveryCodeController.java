package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityMfaRecoveryCodeIssueRequest;
import com.ixayda.iam.dto.IdentityMfaRecoveryCodesResponse;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityMfaRecoveryCodes;

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
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentityMfaRecoveryCodeController {

	private final IdentityMfaRecoveryCodes recoveryCodes;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityMfaRecoveryCodeController(IdentityMfaRecoveryCodes recoveryCodes) {
		this.recoveryCodes = recoveryCodes;
	}

	@InitBinder("recoveryCodeIssuance")
	void recoveryCodeBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "regenerateCurrentMfaRecoveryCodes", summary = "重新生成本人 MFA 恢复码", description = "需要有效密码会话、已激活的 TOTP 因素及本次操作的新验证码，不要求管理员资格或已提升的管理会话。成功替换全部旧恢复码，一次性交付 10 个新码；没有重新读取明文的接口。不会提升管理权限、轮换会话或延长密码及管理认证的绝对期限。仅接受 code 和 CSRF，拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。响应交付失败后须用新验证码重新生成；旧组不会恢复。明文不得放入 URL、日志或浏览器持久存储。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "新恢复码，仅本次交付；旧组全部失效", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityMfaRecoveryCodesResponse.class)))
	@ApiResponse(responseCode = "400", description = "因素或验证码被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "TOTP 共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityMfaRecoveryCodeIssueRequest.class)))
	@PostMapping(path = "/api/me/mfa/recovery-codes", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> regenerate(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("recoveryCodeIssuance") IdentityMfaRecoveryCodeIssueRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(request, response);
		}
		var context = new TotpAuthenticationContext("browser:mfa-recovery-codes", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		IdentityMfaRecoveryCodes.Result result;
		try {
			result = this.recoveryCodes.issueForSession(userId, session.getId(), version, authenticatedAt, command.code(), context, () -> {
				try { response.flushBuffer(); }
				catch (IOException ex) { throw new UncheckedIOException(ex); }
			});
		}
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		return switch (result.status()) {
			case ISSUED -> {
				var issued = result.codeSet();
				yield ResponseEntity.ok(new IdentityMfaRecoveryCodesResponse(issued.generationId(), issued.codes(), issued.issuedAt()));
			}
			case INVALID_SESSION -> invalidSession(request, response);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Recovery code regeneration rejected");
		};
	}

	private ResponseEntity<?> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

}
