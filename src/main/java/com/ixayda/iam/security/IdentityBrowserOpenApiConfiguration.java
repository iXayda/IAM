package com.ixayda.iam.security;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.HeaderParameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Describes authentication filters and their shared HTTP boundary. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "springdoc.api-docs.enabled", havingValue = "true")
class IdentityBrowserOpenApiConfiguration {

	@Bean
	OpenApiCustomizer browserAuthenticationOpenApi() {
		return openApi -> {
			openApi.getComponents().addSchemas("IdentityErrorResponse", new ObjectSchema()
					.addProperty("code", new StringSchema().description("稳定的错误标识"))
					.addProperty("message", new StringSchema().description("可展示的通用错误提示"))
					.required(List.of("code", "message")));
			openApi.path("/login", new PathItem().post(login()));
			openApi.path("/logout", new PathItem().post(logout()));
			openApi.getPaths().values().forEach(path -> path.readOperations().forEach(operation ->
					commonResponses().forEach((status, response) -> operation.getResponses().putIfAbsent(status, response))));
		};
	}

	private static Operation login() {
		return publicOperation("loginWithPassword", "提交密码登录")
				.description("先获取 /api/csrf，携带所属会话的 __Host-IAMSESSION Cookie 和 X-CSRF-TOKEN 请求头。"
						+ "账号原样提交，不去除首尾空白。成功轮换会话标识，返回 204；拒绝返回 401 和统一错误，不重定向。登录后重新获取 CSRF 令牌。")
				.addParametersItem(csrfHeader())
				.requestBody(new RequestBody().required(true).content(new Content().addMediaType("application/json",
						new MediaType().example(Map.of("username", "user.example", "password", "<account-password>"))
								.schema(new ObjectSchema()
								.addProperty("username", new StringSchema().description("登录账号"))
								.addProperty("password", new StringSchema().format("password").writeOnly(true).description("账号密码"))
								.required(List.of("username", "password")).additionalProperties(false)))))
				.responses(new ApiResponses()
						.addApiResponse("204", new ApiResponse().description("已登录，会话 Cookie 已轮换，无响应体")
								.addHeaderObject("Set-Cookie", sessionCookie("设置已认证会话 Cookie")))
						.addApiResponse("401", errorResponse("账号密码错误、账号不可用或密码认证受限，统一返回 INVALID_CREDENTIALS"))
						.addApiResponse("403", errorResponse("CSRF_INVALID：令牌缺失或无效"))
						.addApiResponse("415", errorResponse("UNSUPPORTED_MEDIA_TYPE：需要 application/json")));
	}

	private static Operation logout() {
		return publicOperation("logoutBrowserSession", "结束当前浏览器会话")
				.description("携带当前会话 Cookie 和从 /api/csrf 取得的 X-CSRF-TOKEN 请求头，无需请求体。"
						+ "允许匿名会话退出。成功返回 204，不重定向；退出后重新获取 CSRF 令牌。")
				.addParametersItem(csrfHeader())
				.responses(new ApiResponses()
						.addApiResponse("204", new ApiResponse().description("当前会话已结束，无响应体")
								.addHeaderObject("Set-Cookie", sessionCookie("清除当前会话 Cookie")))
						.addApiResponse("403", errorResponse("CSRF_INVALID：令牌缺失或无效")));
	}

	private static Operation publicOperation(String id, String summary) {
		return new Operation().operationId(id).summary(summary).tags(List.of("authentication")).security(List.of());
	}

	private static HeaderParameter csrfHeader() {
		var header = new HeaderParameter();
		header.name("X-CSRF-TOKEN").required(true).description("从同一会话的 /api/csrf 响应取得的 token").schema(new StringSchema());
		return header;
	}

	private static Header sessionCookie(String description) {
		return new Header().description(description + "：__Host-IAMSESSION，Secure、HttpOnly、Path=/、SameSite=Lax")
				.schema(new StringSchema());
	}

	private static ApiResponse errorResponse(String description) {
		return new ApiResponse().description(description).content(new Content().addMediaType("application/json",
				new MediaType().schema(new Schema<>().$ref("#/components/schemas/IdentityErrorResponse"))));
	}

	private static ApiResponses commonResponses() {
		return new ApiResponses()
				.addApiResponse("400", errorResponse("BAD_REQUEST：请求格式无效，或未使用 HTTPS"))
				.addApiResponse("401", errorResponse("UNAUTHENTICATED：未登录或登录身份失效"))
				.addApiResponse("413", errorResponse("PAYLOAD_TOO_LARGE：请求体超过允许大小"))
				.addApiResponse("429", errorResponse("TOO_MANY_REQUESTS：入口限流，请按 Retry-After 响应头重试")
						.addHeaderObject("Retry-After", new Header().description("重试等待秒数")
								.schema(new IntegerSchema().minimum(BigDecimal.ONE))))
				.addApiResponse("503", errorResponse("AUTHENTICATION_UNAVAILABLE 或 SERVICE_UNAVAILABLE：服务暂不可用"));
	}
}
