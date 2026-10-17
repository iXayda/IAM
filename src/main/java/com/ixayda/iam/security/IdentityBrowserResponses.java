package com.ixayda.iam.security;

import java.io.IOException;
import java.util.Map;

import tools.jackson.databind.json.JsonMapper;

import jakarta.servlet.http.HttpServletResponse;

final class IdentityBrowserResponses {

	private static final JsonMapper JSON = new JsonMapper();

	private IdentityBrowserResponses() { }

	static void error(HttpServletResponse response, Error error) throws IOException {
		response.setStatus(error.status);
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(JSON.writeValueAsString(Map.of("code", error.name(), "message", error.message)));
	}

	enum Error {
		BAD_REQUEST(400, "请求格式无效"),
		UNAUTHENTICATED(401, "请先登录"),
		INVALID_CREDENTIALS(401, "账号或密码错误"),
		FORBIDDEN(403, "无权执行此操作"),
		CSRF_INVALID(403, "安全凭据缺失或已失效，请重试"),
		PAYLOAD_TOO_LARGE(413, "请求体超过允许的大小"),
		UNSUPPORTED_MEDIA_TYPE(415, "请使用 application/json 提交登录请求"),
		TOO_MANY_REQUESTS(429, "请求过于频繁，请稍后重试"),
		AUTHENTICATION_UNAVAILABLE(503, "认证服务暂不可用"),
		SERVICE_UNAVAILABLE(503, "服务暂不可用");

		private final int status;
		private final String message;

		Error(int status, String message) {
			this.status = status;
			this.message = message;
		}
	}
}
