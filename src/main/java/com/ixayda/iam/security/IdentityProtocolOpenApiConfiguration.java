package com.ixayda.iam.security;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Describes the native protocol filters alongside the enabled HTTP capabilities. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = { "springdoc.api-docs.enabled", "iam.protocol.issuer" })
class IdentityProtocolOpenApiConfiguration {

	@Bean
	OpenApiCustomizer protocolOpenApi() {
		return openApi -> {
			openApi.getComponents().addSecuritySchemes("protocolClient", new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("basic")
					.description("保密 Web/BFF 客户端使用 client_secret_basic；对客户端标识与秘密分别进行 form 编码，再拼接冒号并进行 Base64 编码。秘密仅由客户端服务端保存。"));
			openApi.getComponents().addSchemas("IdentityProtocolError", new ObjectSchema()
					.addProperty("error", new StringSchema().description("OAuth 错误标识，不包含请求值或内部异常详情"))
					.required(List.of("error")).additionalProperties(false));
			openApi.path(IdentityProtocolResponses.TOKEN_ENDPOINT, new PathItem().post(token()));
		};
	}

	private static Operation token() {
		var code = new ObjectSchema().addProperty("grant_type", new StringSchema()._enum(List.of("authorization_code")))
				.addProperty("code", secret("尚未消费的授权码"))
				.addProperty("redirect_uri", new StringSchema().format("uri").description("与原授权请求及登记值逐字一致的回调地址"))
				.addProperty("code_verifier", secret("原 PKCE S256 verifier，43–128 个允许的 ASCII 字符"))
				.required(List.of("grant_type", "code", "redirect_uri", "code_verifier"));
		var refresh = new ObjectSchema().addProperty("grant_type", new StringSchema()._enum(List.of("refresh_token")))
				.addProperty("refresh_token", secret("当前有效的刷新凭据，成功后立即以返回的新值替换"))
				.addProperty("scope", new StringSchema().description("可选、空格分隔；省略时保留当前 scope，仅允许收窄。移除 offline_access 后停止返回刷新凭据，移除 openid 后停止返回 ID Token。"))
				.required(List.of("grant_type", "refresh_token"));
		var response = new ObjectSchema().addProperty("access_token", new StringSchema().description("业务 Access Token；不能作为 IAM 管理权限"))
				.addProperty("token_type", new StringSchema()._enum(List.of("Bearer")))
				.addProperty("expires_in", new IntegerSchema().minimum(BigDecimal.ZERO).maximum(BigDecimal.valueOf(300)))
				.addProperty("scope", new StringSchema().description("本次实际获授的范围"))
				.addProperty("refresh_token", new StringSchema().description("实际获授 offline_access 时返回；成功刷新后替换旧值"))
				.addProperty("id_token", new StringSchema().description("实际获授 openid 时返回，最长 300 秒；由客户端核验，不能作为业务 Access Token"))
				.required(List.of("access_token", "token_type", "expires_in", "scope"));
		return new Operation().operationId("exchangeApplicationTokens").summary("兑换授权码或刷新应用凭据").tags(List.of("protocol"))
				.security(List.of(new SecurityRequirement().addList("protocolClient")))
				.description("由保密应用的服务端通过 HTTPS 调用，仅支持 client_secret_basic 和 UTF-8 form 请求体。"
						+ "不使用 IAM Cookie 或浏览器 CSRF 令牌，不创建或更新浏览器会话；不开放跨源凭据访问。"
						+ "拒绝查询串、重复参数、正文客户端认证和 DPoP；不能通过 resource、audience 等参数扩大原授权。"
						+ "授权码绑定原客户端、精确回调和 PKCE S256。刷新凭据单次使用，闲置期限最多 7 天，家族绝对期限最多 30 天。"
						+ "有效证明的授权码重放或刷新凭据重放会撤销对应应用授权，不能将响应丢失后的旧凭据重试当作幂等调用。"
						+ "仅在持久化和必需审计提交后交付凭据；响应与错误均禁止缓存。")
				.requestBody(new RequestBody().required(true).content(new Content().addMediaType("application/x-www-form-urlencoded",
						new MediaType().schema(new ComposedSchema().oneOf(List.of(code, refresh)))
								.example(Map.of("grant_type", "authorization_code", "code", "<authorization-code>", "redirect_uri", "https://application.example/callback", "code_verifier", "<original-pkce-verifier>")))))
				.responses(new ApiResponses()
						.addApiResponse("200", new ApiResponse().description("凭据及成功审计已提交").content(new Content().addMediaType("application/json", new MediaType().schema(response))))
						.addApiResponse("400", error("invalid_request、invalid_grant、invalid_scope 或 unsupported_grant_type；错误证明不消费原凭据"))
						.addApiResponse("401", error("invalid_client：客户端凭据缺失、错误或客户端不可用")
								.addHeaderObject("WWW-Authenticate", new Header().schema(new StringSchema()).description("Basic realm=\"iam/token\"")))
						.addApiResponse("405", error("仅支持 POST，返回 Allow: POST").addHeaderObject("Allow", new Header().schema(new StringSchema()._enum(List.of("POST")))))
						.addApiResponse("413", error("invalid_request：请求体超过 8 KiB"))
						.addApiResponse("415", error("invalid_request：需要 UTF-8 application/x-www-form-urlencoded"))
						.addApiResponse("429", error("temporarily_unavailable：共享入口限流")
								.addHeaderObject("Retry-After", new Header().schema(new IntegerSchema().minimum(BigDecimal.ONE)).description("等待秒数")))
						.addApiResponse("503", error("server_error：存储、审计或签发依赖不可用；不得切换为离线放行")));
	}

	private static Schema<?> secret(String description) { return new StringSchema().format("password").writeOnly(true).description(description); }

	private static ApiResponse error(String description) {
		return new ApiResponse().description(description).content(new Content().addMediaType("application/json",
				new MediaType().schema(new Schema<>().$ref("#/components/schemas/IdentityProtocolError"))));
	}

}
