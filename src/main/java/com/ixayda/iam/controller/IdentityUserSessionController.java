package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityUserSessionRevocationRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserSessionManagement;

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
@Tag(name = "user-sessions", description = "管理员强制用户全部下线，需要当前管理资格、密码和 TOTP 会话，以及本次操作的新 TOTP。")
public class IdentityUserSessionController {

	private final IdentityUserSessionManagement management;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityUserSessionController(IdentityUserSessionManagement management, IdentityAdministratorSessions administrators) {
		this.management = management; this.administrators = administrators;
	}

	@InitBinder("sessionRevocation")
	void revocationBinding(ExtendedServletRequestDataBinder binder) { binder.setDeclarativeBinding(true); binder.setHeaderPredicate(header -> false); }

	@Operation(operationId = "revokeAllUserSessions", summary = "强制用户全部下线", description = "仅接受用户 UUID 路径参数和 code 表单字段，可用同一会话 X-CSRF-TOKEN 或 _csrf。无查询串。撤销目标全部浏览器会话、授权码、应用授权和刷新家族，不受分页限制。"
			+ "账号状态、密码和管理资格保持；目标可重新认证。管理员可下线自己，操作成功后清除其 Cookie。目标不存在返回 404 并回滚本次 TOTP；其他授权成功的操作均消费本次 TOTP。"
			+ "接入应用须执行在线校验；纯离线 Token 保留剩余签名有效期窗口，IAM 不直接删除应用本地会话。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 CSRF；也接受 _csrf 表单字段", schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityUserSessionRevocationRequest.class)))
	@ApiResponse(responseCode = "204", description = "目标的全部下线事务已提交", content = @Content)
	@ApiResponse(responseCode = "400", description = "输入或 TOTP 无效或重放", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "401", description = "当前密码会话失效或未登录", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "目标用户不存在", content = @Content)
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "TOTP 或入口限流", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "503", description = "会话、撤销或必需审计未能提交，不交付成功", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/users/{userId}/sessions/revoke-all", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<?> revokeAll(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String userId,
			@Parameter(hidden = true) @ModelAttribute("sessionRevocation") IdentityUserSessionRevocationRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = UUID.fromString(userId); if (!id.toString().equals(userId) || request.getQueryString() != null
				|| !Set.of("code", "_csrf").containsAll(request.getParameterMap().keySet())
				|| request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) { throw new IllegalArgumentException("Invalid session revocation request"); }
		UUID correlation = UUID.randomUUID(); var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlation, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var evidence = stored instanceof IdentityAdministratorAuthentication current ? current : null;
		var context = new IdentityAdministratorContext(actorId, session.getId(), version, authenticatedAt, evidence,
				new TotpAuthenticationContext("browser:admin-user-sessions", InetAddress.getByName(request.getRemoteAddr()), correlation));
		IdentityUserSessionManagement.Result result;
		try { result = this.management.revokeAll(context, id, command.code(), () -> { try { response.flushBuffer(); } catch (IOException ex) { throw new UncheckedIOException(ex); } }); }
		catch (RuntimeException ex) { session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true); throw ex; }
		return switch (result.status()) {
			case COMPLETED -> {
				if (result.currentSessionRevoked()) { SecurityContextHolder.clearContext(); this.logout.logout(request, response, null); }
				yield ResponseEntity.noContent().build();
			}
			case INVALID_SESSION -> invalidSession(actorId, correlation, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case REJECTED -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.BAD_REQUEST);
			case THROTTLED -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.TOO_MANY_REQUESTS);
			case NOT_FOUND -> ResponseEntity.notFound().build();
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlation, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext(); this.logout.logout(request, response, null); this.administrators.recordAccessDenied(actorId, correlation);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<?> invalidSessionRevocationRequest() { return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.BAD_REQUEST); }
}
