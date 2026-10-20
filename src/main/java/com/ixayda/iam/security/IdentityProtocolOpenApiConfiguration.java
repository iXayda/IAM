package com.ixayda.iam.security;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.parameters.QueryParameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.beans.factory.ObjectProvider;
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
	OpenApiCustomizer protocolOpenApi(ObjectProvider<IdentityAuthorizationEndpoint> authorization) {
		return openApi -> {
			openApi.getComponents().addSecuritySchemes("protocolClient", new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("basic")
					.description("保密 Web/BFF 客户端使用 client_secret_basic；对客户端标识与秘密分别进行 form 编码，再拼接冒号并进行 Base64 编码。秘密仅由客户端服务端保存。"));
			openApi.getComponents().addSecuritySchemes("applicationBearer", new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")
					.description("IAM 签发的有效业务 Access Token，必须实际获授 openid；不能使用 ID Token、刷新凭据或 IAM Cookie。"));
			openApi.getComponents().addSchemas("IdentityProtocolError", new ObjectSchema()
					.addProperty("error", new StringSchema().description("OAuth 错误标识，不包含请求值或内部异常详情"))
					.required(List.of("error")).additionalProperties(false));
			openApi.path(IdentityProtocolResponses.TOKEN_ENDPOINT, new PathItem().post(token()));
			openApi.path(IdentityProtocolResponses.JWK_SET_ENDPOINT, new PathItem().get(publicKeys()));
			openApi.path(IdentityProtocolResponses.USER_INFO_ENDPOINT, new PathItem().get(userInfo("getUserInfo")).post(userInfo("postUserInfo")));
			if (authorization.getIfAvailable() != null) {
				openApi.path(IdentityProtocolResponses.AUTHORIZATION_ENDPOINT, new PathItem().get(authorize()));
				openApi.path(IdentityProtocolResponses.OIDC_DISCOVERY_ENDPOINT, new PathItem().get(discovery(true)));
				openApi.path(IdentityProtocolResponses.OAUTH_DISCOVERY_ENDPOINT, new PathItem().get(discovery(false)));
				openApi.getPaths().forEach((path, item) -> {
					if (path.startsWith(IdentityProtocolResponses.INTERACTION_ENDPOINT + "/")) { item.readOperations().forEach(operation -> operation.setSecurity(List.of())); }
				});
			}
		};
	}

	private static Operation discovery(boolean oidc) {
		var configuration = new ObjectSchema().addProperty("issuer", new StringSchema().format("uri"))
				.addProperty("authorization_endpoint", new StringSchema().format("uri"))
				.addProperty("token_endpoint", new StringSchema().format("uri"))
				.addProperty("jwks_uri", new StringSchema().format("uri"));
		for (var item : Map.of("token_endpoint_auth_methods_supported", List.of("client_secret_basic"), "response_types_supported", List.of("code"),
				"response_modes_supported", List.of("query"), "grant_types_supported", List.of("authorization_code", "refresh_token"),
				"code_challenge_methods_supported", List.of("S256"), "scopes_supported", List.of("openid", "profile", "offline_access")).entrySet()) {
			configuration.addProperty(item.getKey(), new ArraySchema().items(new StringSchema()._enum(item.getValue())));
		}
		if (oidc) {
			configuration.addProperty("userinfo_endpoint", new StringSchema().format("uri"));
			configuration.addProperty("subject_types_supported", new ArraySchema().items(new StringSchema()._enum(List.of("public"))));
			configuration.addProperty("id_token_signing_alg_values_supported", new ArraySchema().items(new StringSchema()._enum(List.of("RS256"))));
			configuration.addProperty("claims_supported", new ArraySchema().items(new StringSchema()));
			for (String name : List.of("claims_parameter_supported", "request_parameter_supported", "request_uri_parameter_supported")) {
				configuration.addProperty(name, new io.swagger.v3.oas.models.media.BooleanSchema()._enum(List.of(false)));
			}
		}
		return new Operation().operationId(oidc ? "getOpenIdConfiguration" : "getAuthorizationServerMetadata")
				.summary(oidc ? "查询 OpenID Provider 配置" : "查询 OAuth 授权服务器元数据").tags(List.of("protocol")).security(List.of())
				.description("公开 HTTPS GET，无需 Cookie 或客户端认证；不接受查询串或正文，不读取或更新浏览器会话。"
						+ "issuer 与端点固定取自配置；只声明已启用的授权码、刷新、PKCE S256、client_secret_basic 及 RS256 能力。"
						+ "不声明未开放的注册、设备授权、PAR、Token Exchange、Introspection、协议退出、DPoP 或 mTLS。"
						+ "客户端必须核对返回 issuer 与预配置信任值逐字一致；元数据可访问不代表当前签发或验证依赖健康。")
				.responses(new ApiResponses().addApiResponse("200", new ApiResponse().description("固定 issuer 的实际协议能力")
						.content(new Content().addMediaType("application/json", new MediaType().schema(configuration))))
						.addApiResponse("400", error("invalid_request：不接受查询串或请求体"))
						.addApiResponse("405", error("只接受 GET").addHeaderObject("Allow", new Header().schema(new StringSchema()._enum(List.of("GET")))))
						.addApiResponse("413", error("invalid_request：超过共享请求体上限"))
						.addApiResponse("429", error("temporarily_unavailable：共享入口限流"))
						.addApiResponse("503", error("server_error：元数据响应不可用")));
	}

	private static Operation authorize() {
		var operation = new Operation().operationId("authorizeApplication").summary("发起应用的 OIDC 授权码请求").tags(List.of("protocol")).security(List.of())
				.description("由应用导航浏览器到此 GET 入口，授权码流程要求 PKCE S256。使用当前有效 IAM Cookie 完成 SSO；需要登录、账号选择或确认时，导航到预配置的同源独立身份前端。"
						+ "IAM 提供协议及交互 API，不提供登录页面。前端导航只携带短期交互句柄，原始回调、state、nonce 和 PKCE 保存在服务器。"
						+ "仅接受查询参数，无请求体；重复参数拒绝，未知参数忽略，不支持请求对象、PAR、外部 resource/audience 或 DPoP。"
						+ "回调必须与登记地址逐字匹配，不可用客户端或无效回调只返回本地错误。prompt=none 不打开交互界面；RP 必须比较 state，验证 ID Token 的 issuer、签名、audience、期限及 nonce。"
						+ "应用服务端持有客户端秘密，前端不处理秘密或 Token 兑换。")
				.responses(new ApiResponses().addApiResponse("302", new ApiResponse().description("导航到精确登记回调，或固定身份前端；回调携带 code/state 或 error/state")
						.addHeaderObject("Location", new Header().schema(new StringSchema().format("uri"))))
						.addApiResponse("400", error("invalid_request：无效客户端、回调、重复参数或请求格式；不向未验证地址重定向"))
						.addApiResponse("405", error("只接受 GET").addHeaderObject("Allow", new Header().schema(new StringSchema()._enum(List.of("GET")))))
						.addApiResponse("413", error("invalid_request：超过共享请求体上限"))
						.addApiResponse("429", error("temporarily_unavailable：入口或待处理交互数量受限"))
						.addApiResponse("503", error("server_error：持久化、签发或必需审计不可用")));
		for (var item : List.of(
				new String[] {"response_type", "code", "固定授权码响应类型", "true"},
				new String[] {"client_id", "", "登记的保密客户端 UUID", "true"},
				new String[] {"redirect_uri", "", "逐字匹配的 HTTPS 回调", "true"},
				new String[] {"scope", "", "空格分隔，包含 openid；受客户端允许范围约束", "true"},
				new String[] {"state", "", "应用生成且在回调比较的不可预测关联值，最多 512 个可见 ASCII 字符", "true"},
				new String[] {"code_challenge", "", "SHA-256 的规范 base64url 编码，43 字符", "true"},
				new String[] {"code_challenge_method", "S256", "仅支持 S256", "true"},
				new String[] {"nonce", "", "可选，出现时最多 256 个可见 ASCII 字符；RP 与 ID Token 比较", "false"},
				new String[] {"prompt", "", "none 或 login、consent、select_account 的不重复组合；none 必须单独使用", "false"},
				new String[] {"max_age", "", "可选非负整数秒；0 要求新的登录", "false"},
				new String[] {"response_mode", "query", "仅支持 query", "false"})) {
			var schema = new StringSchema(); if (!item[1].isEmpty()) { schema._enum(List.of(item[1])); }
			operation.addParametersItem(new QueryParameter().name(item[0]).required(Boolean.parseBoolean(item[3])).description(item[2]).schema(schema));
		}
		return operation;
	}

	private static Operation userInfo(String operationId) {
		var claims = new ObjectSchema().addProperty("sub", new StringSchema().format("uuid").description("稳定主体标识，客户端须与已验证 ID Token 的 sub 比较"))
				.addProperty("name", new StringSchema().description("实际获授 profile 时返回当前显示名称"))
				.addProperty("preferred_username", new StringSchema().description("实际获授 profile 时返回当前登录标识"))
				.required(List.of("sub")).additionalProperties(false);
		return new Operation().operationId(operationId).summary("查询 OIDC 用户资料").tags(List.of("protocol"))
				.security(List.of(new SecurityRequirement().addList("applicationBearer")))
				.description("通过 Authorization: Bearer 调用，GET 与 POST 均不接受查询串、请求体、重复认证头或 DPoP。"
						+ "在同一事务内完成严格验签、当前用户及应用授权校验和实际 scope 的资料投影；必须实际具有 openid，profile 控制姓名与用户名。"
						+ "原始获批或客户端配置的 scope 不能代替本次 Token 的实际范围，资料来自当前用户记录。"
						+ "响应禁止缓存，不读取或更新 IAM 浏览器会话，也不授予管理权限；客户端须核对 sub 与其已验证 ID Token 一致。"
						+ "未提供 Bearer 认证时返回空正文的 401 challenge；其他拒绝返回固定 OAuth 错误并记录必需审计。")
				.responses(new ApiResponses()
						.addApiResponse("200", new ApiResponse().description("由实际 scope 允许的当前用户资料").content(new Content().addMediaType("application/json", new MediaType().schema(claims))))
						.addApiResponse("400", error("invalid_request：无效传输、查询串、请求体或重复认证头")
								.addHeaderObject("WWW-Authenticate", new Header().schema(new StringSchema()).description("Bearer challenge，含 error=\"invalid_request\"")))
						.addApiResponse("401", error("无 Bearer 时正文为空；其他情况为 invalid_token，含过期、撤销、签名或用途错误")
								.addHeaderObject("WWW-Authenticate", new Header().schema(new StringSchema()).description("Bearer realm=\"iam/userinfo\"，存在无效 Bearer 时附带 error=\"invalid_token\"")))
						.addApiResponse("403", error("insufficient_scope：当前有效 Access Token 未实际获授 openid")
								.addHeaderObject("WWW-Authenticate", new Header().schema(new StringSchema()).description("Bearer challenge，含 error=\"insufficient_scope\" 和 scope=\"openid\"")))
						.addApiResponse("405", error("仅支持 GET、POST").addHeaderObject("Allow", new Header().schema(new StringSchema()._enum(List.of("GET, POST")))))
						.addApiResponse("413", error("invalid_request：请求体超过 8 KiB"))
						.addApiResponse("429", error("temporarily_unavailable：共享入口限流").addHeaderObject("Retry-After", new Header().schema(new IntegerSchema().minimum(BigDecimal.ONE))))
						.addApiResponse("503", error("server_error：验证依赖、用户存储或必需拒绝审计不可用")));
	}

	private static Operation publicKeys() {
		var key = new ObjectSchema().addProperty("kty", new StringSchema()._enum(List.of("RSA")))
				.addProperty("kid", new StringSchema().format("uuid").description("持久签名密钥标识"))
				.addProperty("use", new StringSchema()._enum(List.of("sig")))
				.addProperty("alg", new StringSchema()._enum(List.of("RS256")))
				.addProperty("n", new StringSchema().description("RSA 公钥模数，Base64url 编码"))
				.addProperty("e", new StringSchema().description("RSA 公钥指数，Base64url 编码"))
				.required(List.of("kty", "kid", "use", "alg", "n", "e")).additionalProperties(false);
		return new Operation().operationId("getPublicSigningKeys").summary("查询 Token 签名公钥").tags(List.of("protocol"))
				.security(List.of()).description("公开 HTTPS GET 入口，无需 IAM Cookie 或客户端凭据，不读取或更新浏览器会话。"
						+ "返回持久签名身份的 RSA 公钥，不包含私钥或对称秘密；不接受查询串及请求体。"
						+ "公钥不能代替 issuer、audience、算法、用途、期限和在线授权状态校验。"
						+ "响应禁止缓存；资源侧任何缓存须符合其明确接受的密钥更新与撤销窗口。公钥存储不可用时返回 503，不生成临时替代密钥。")
				.responses(new ApiResponses()
						.addApiResponse("200", new ApiResponse().description("JWK Set，仅包含公开验证材料").content(new Content().addMediaType("application/json",
								new MediaType().schema(new ObjectSchema().addProperty("keys", new ArraySchema().items(key).minItems(1)).required(List.of("keys")).additionalProperties(false)))))
						.addApiResponse("400", error("invalid_request：不接受查询串或请求体"))
						.addApiResponse("405", error("仅支持 GET，返回 Allow: GET").addHeaderObject("Allow", new Header().schema(new StringSchema()._enum(List.of("GET")))))
						.addApiResponse("413", error("invalid_request：请求体超过 8 KiB"))
						.addApiResponse("429", error("temporarily_unavailable：共享入口限流").addHeaderObject("Retry-After", new Header().schema(new IntegerSchema().minimum(BigDecimal.ONE))))
						.addApiResponse("503", error("server_error：公钥状态缺失、损坏或存储不可用")));
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
