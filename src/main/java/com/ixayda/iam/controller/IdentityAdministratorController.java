package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.Map;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityAdministratorAuthenticationRequest;
import com.ixayda.iam.dto.IdentityAdministratorResponse;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministratorAuthentications;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUsers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import tools.jackson.databind.json.JsonMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentityAdministratorController {

	private final IdentityAdministratorAuthentications authentications;
	private final IdentityAdministratorSessions administrators;
	private final IdentityUsers users;
	private final CsrfTokenRepository csrfTokens;
	private final HttpSessionSecurityContextRepository contexts = new HttpSessionSecurityContextRepository();
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityAdministratorController(IdentityAdministratorAuthentications authentications, IdentityAdministratorSessions administrators,
			IdentityUsers users, CsrfTokenRepository csrfTokens) {
		this.authentications = authentications;
		this.administrators = administrators;
		this.users = users;
		this.csrfTokens = csrfTokens;
	}

	@InitBinder("administratorAuthentication")
	void authenticationBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "verifyAdministratorTotp", summary = "验证管理员 TOTP", description = "仅具有管理员资格的密码会话可提交六位 code。成功轮换会话 Cookie 及 CSRF 令牌，取得最多 900 秒的管理资格；随后重新获取 /api/csrf。拒绝查询参数、额外及重复字段；不提供验证页面。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "管理验证完成，Cookie 已轮换，无响应体", content = @Content)
	@ApiResponse(responseCode = "400", description = "MFA_REJECTED 或请求格式无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "403", description = "管理员资格不足或 CSRF 无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "MFA_THROTTLED 或入口限流", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityAdministratorAuthenticationRequest.class)))
	@PostMapping(path = "/admin/mfa", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public void authenticate(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("administratorAuthentication") IdentityAdministratorAuthenticationRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID correlationId = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			invalidSession(userId, correlationId, request, response);
			return;
		}
		String originalId = session.getId();
		var context = new TotpAuthenticationContext("browser:admin-mfa", InetAddress.getByName(request.getRemoteAddr()), correlationId);
		IdentityAdministratorAuthentications.Result result;
		try {
			result = this.authentications.authenticate(userId, originalId, version, authenticatedAt, command.code(), context, verified -> {
				session.setAttribute(IdentityBrowserSessions.ORIGINAL_ID, originalId);
				session.setAttribute(IdentityBrowserSessions.MFA_PENDING, true);
				session.setAttribute(IdentityAdministratorSessions.AUTHENTICATION, verified);
				request.changeSessionId();
				var authentication = UsernamePasswordAuthenticationToken.authenticated(userId, null,
						this.administrators.authorities(userId, authenticatedAt, verified));
				var security = SecurityContextHolder.createEmptyContext();
				security.setAuthentication(authentication);
				SecurityContextHolder.setContext(security);
				this.contexts.saveContext(security, request, response);
				new CsrfAuthenticationStrategy(this.csrfTokens).onAuthentication(authentication, request, response);
				((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken();
				response.setStatus(204);
				try {
					// The outer response boundary buffers publication; Spring Session saves inside this transaction.
					response.flushBuffer();
				}
				catch (IOException ex) { throw new UncheckedIOException(ex); }
				return session.getId();
			});
		}
		catch (RuntimeException ex) {
			// An outer commit can fail after the mutable session was saved; its finalizer must never retry it.
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		if (result == IdentityAdministratorAuthentications.Result.INVALID_SESSION) {
			invalidSession(userId, correlationId, request, response);
		}
		else if (result != IdentityAdministratorAuthentications.Result.AUTHENTICATED) {
			response.setStatus(result == IdentityAdministratorAuthentications.Result.THROTTLED ? 429 : 400);
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(new JsonMapper().writeValueAsString(Map.of(
					"code", result == IdentityAdministratorAuthentications.Result.THROTTLED ? "MFA_THROTTLED" : "MFA_REJECTED",
					"message", result == IdentityAdministratorAuthentications.Result.THROTTLED
							? "Verification temporarily unavailable. Try again later." : "Verification rejected. Enter a new authenticator code.")));
		}
	}

	private void invalidSession(UUID userId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(userId, correlationId);
		response.setStatus(401);
	}

	@Operation(operationId = "getCurrentAdministrator", summary = "查询本人管理身份", description = "需要有效的管理员资格、密码认证及未过期的 TOTP 管理验证；只返回当前管理员身份。")
	@ApiResponse(responseCode = "200", description = "当前管理员身份")
	@ApiResponse(responseCode = "403", description = "管理资格或 MFA 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@GetMapping("/api/admin/me")
	public IdentityAdministratorResponse me(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId) {
		var user = this.users.findById(userId).orElseThrow();
		return new IdentityAdministratorResponse(user.id(), user.username(), user.displayName());
	}

}
