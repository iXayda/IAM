package com.ixayda.iam.security;

import java.util.List;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "springdoc.api-docs.enabled", havingValue = "true")
class IdentityHealthOpenApiConfiguration {

	@Bean
	OpenApiCustomizer healthOpenApi() {
		return openApi -> {
			openApi.getComponents().addSchemas("IdentityHealth", new ObjectSchema().addProperty("status",
					new StringSchema()._enum(List.of("UP", "DOWN", "OUT_OF_SERVICE", "UNKNOWN"))).required(List.of("status")).additionalProperties(false));
			for (String path : IdentityHealthRequestFilter.PATHS) {
				boolean live = path.endsWith("liveness") || path.equals("/livez");
				var operation = new Operation().operationId((live ? "getLiveness" : "getReadiness") + (path.startsWith("/actuator/") ? "Group" : "Probe"))
						.summary(live ? "查询进程存活状态" : "查询接收流量的就绪状态").tags(List.of("operations")).security(List.of())
						.description("公开 HTTPS GET，不要求 Cookie 或 CSRF，不读取浏览器会话；不接受查询串或请求体，只返回总体 status。"
								+ (live ? "仅检查进程存活状态，不依赖数据库或审计写入，不受浏览器限流预算影响。" : "检查接收流量状态、审计存储可写权限与已知故障、授权保护配置及当前签发材料。"
										+ "就绪查询不生成审计事件；已知审计故障须由真实业务审计成功提交或修复后重启解除。"))
						.responses(new ApiResponses().addApiResponse("200", status("UP：状态正常"))
								.addApiResponse("503", status("DOWN 或 OUT_OF_SERVICE：不接收对应流量"))
								.addApiResponse("400", error("BAD_REQUEST：不接受查询串或请求体"))
								.addApiResponse("405", error("METHOD_NOT_ALLOWED：只接受 GET")
										.addHeaderObject("Allow", new Header().schema(new StringSchema()._enum(List.of("GET"))))));
				openApi.path(path, new PathItem().get(operation));
			}
		};
	}

	private static ApiResponse status(String description) {
		return new ApiResponse().description(description).content(new Content().addMediaType("application/json", new MediaType().schema(new Schema<>().$ref("#/components/schemas/IdentityHealth"))));
	}
	private static ApiResponse error(String description) {
		return new ApiResponse().description(description).content(new Content().addMediaType("application/json", new MediaType().schema(new Schema<>().$ref("#/components/schemas/IdentityErrorResponse"))));
	}
}
