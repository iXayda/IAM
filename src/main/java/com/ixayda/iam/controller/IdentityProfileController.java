package com.ixayda.iam.controller;

import java.util.UUID;

import com.ixayda.iam.dto.IdentityProfileResponse;
import com.ixayda.iam.service.IdentityUsers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "profile", description = "本人资料")
public class IdentityProfileController {

	private final IdentityUsers users;

	IdentityProfileController(IdentityUsers users) {
		this.users = users;
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
	public IdentityProfileResponse me(@AuthenticationPrincipal UUID userId) {
		var user = this.users.findById(userId).orElseThrow();
		return new IdentityProfileResponse(user.id(), user.username(), user.displayName());
	}

}
