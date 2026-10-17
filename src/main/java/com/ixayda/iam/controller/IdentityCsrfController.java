package com.ixayda.iam.controller;

import com.ixayda.iam.dto.IdentityCsrfResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "authentication", description = "浏览器登录与退出")
public class IdentityCsrfController {

	@GetMapping("/api/csrf")
	@SecurityRequirements
	@Operation(operationId = "getCsrfToken", summary = "获取当前会话的 CSRF 令牌",
			description = "允许匿名访问，必要时创建匿名会话。登录和退出后须重新获取令牌；使用返回的 headerName 和 token 提交后续 POST 请求。")
	public IdentityCsrfResponse csrf(@Parameter(hidden = true) CsrfToken token) {
		return new IdentityCsrfResponse(token.getHeaderName(), token.getToken());
	}
}
