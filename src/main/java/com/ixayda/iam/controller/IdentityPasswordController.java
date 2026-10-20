package com.ixayda.iam.controller;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityPasswordChangeRequest;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityPasswords;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@Tag(name = "passwords", description = "本人密码")
public class IdentityPasswordController {

	private final IdentityPasswords passwords;

	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityPasswordController(IdentityPasswords passwords) {
		this.passwords = passwords;
	}

	@InitBinder("passwordChange")
	void passwordBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "changeCurrentPassword", summary = "修改本人密码",
			description = "使用当前会话及 CSRF 令牌提交当前密码和新密码；成功后撤销本人全部 IAM 登录会话及应用授权并清除 Cookie。拒绝查询参数及重复参数。")
	@ApiResponse(responseCode = "204", description = "密码已修改，全部 IAM 登录会话及应用授权已撤销", content = @Content)
	@ApiResponse(responseCode = "400", description = "密码修改被拒绝；边界拒绝使用 JSON 错误",
			content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")),
					@Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "429", description = "密码验证受限，或入口限流；入口限流包含 Retry-After",
			content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")),
					@Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@Parameter(name = "X-CSRF-TOKEN", in = io.swagger.v3.oas.annotations.enums.ParameterIn.HEADER,
			description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityPasswordChangeRequest.class)))
	@PostMapping(path = "/api/me/password", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<String> change(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("passwordChange") IdentityPasswordChangeRequest command, Authentication authentication,
			HttpServletRequest request, HttpServletResponse response) throws UnknownHostException {
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(request, response);
		}
		var context = new PasswordAuthenticationContext("browser:password-change",
				InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		var result = this.passwords.change(userId, session.getId(), version, authenticatedAt,
				command.currentPassword(), command.newPassword(), context);
		if (result == IdentityPasswords.Result.INVALID_SESSION) {
			return invalidSession(request, response);
		}
		if (result == IdentityPasswords.Result.CHANGED) {
			this.logout.logout(request, response, authentication);
			return ResponseEntity.noContent().build();
		}
		if (result == IdentityPasswords.Result.THROTTLED) {
			return ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Password change unavailable");
		}
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Password change rejected");
	}

	private ResponseEntity<String> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		// Clear the caller before deletion so expired sessions are audited as system invalidation.
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		return ResponseEntity.status(401).build();
	}

}
