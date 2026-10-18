package com.ixayda.iam.controller;

import java.util.UUID;

import com.ixayda.iam.dto.IdentityProfileResponse;
import com.ixayda.iam.dto.IdentityProfileUpdateRequest;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityProfiles;
import com.ixayda.iam.service.IdentityUsers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@Tag(name = "profile", description = "本人资料")
public class IdentityProfileController {

	private final IdentityUsers users;

	private final IdentityProfiles profiles;

	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityProfileController(IdentityUsers users, IdentityProfiles profiles) {
		this.users = users;
		this.profiles = profiles;
	}

	@InitBinder("profileUpdate")
	void profileBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		// Transport headers must not supply missing profile fields during constructor binding.
		binder.setHeaderPredicate(header -> false);
	}

	@GetMapping("/api/me")
	@Operation(operationId = "getCurrentProfile", summary = "查询本人资料")
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "当前用户的资料",
					content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityProfileResponse.class))),
			@ApiResponse(responseCode = "401", description = "未登录或会话失效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse"))),
			@ApiResponse(responseCode = "429", description = "请求限流，请按 Retry-After 响应头重试",
					headers = @Header(name = "Retry-After", description = "重试等待秒数", schema = @Schema(type = "integer", minimum = "1")),
					content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse"))),
			@ApiResponse(responseCode = "503", description = "会话或审计服务暂不可用",
					content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	})
	public IdentityProfileResponse me(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId) {
		var user = this.users.findById(userId).orElseThrow();
		return new IdentityProfileResponse(user.id(), user.username(), user.displayName());
	}

	@Operation(operationId = "updateCurrentProfile", summary = "修改本人显示名", description = "仅修改当前会话用户的显示名；拒绝查询参数、重复参数和额外字段，用户身份取自会话。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "资料已更新", content = @Content)
	@ApiResponse(responseCode = "400", description = "显示名无效或请求被拒绝", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "无权访问或 CSRF 无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
			content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityProfileUpdateRequest.class)))
	@PostMapping(path = "/api/me/profile", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<String> update(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("profileUpdate") IdentityProfileUpdateRequest command, HttpServletRequest request, HttpServletResponse response) {
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(request, response);
		}
		var result = this.profiles.updateDisplayName(userId, session.getId(), version, authenticatedAt,
				command.displayName(), UUID.randomUUID());
		if (result == IdentityProfiles.Result.INVALID_SESSION) {
			return invalidSession(request, response);
		}
		if (result == IdentityProfiles.Result.INVALID_DISPLAY_NAME) {
			return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Profile update rejected");
		}
		return ResponseEntity.noContent().build();
	}

	private ResponseEntity<String> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		return ResponseEntity.status(401).build();
	}

}
