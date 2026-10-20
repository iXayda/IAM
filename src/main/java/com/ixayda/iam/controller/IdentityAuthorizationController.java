package com.ixayda.iam.controller;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import com.ixayda.iam.dto.IdentityAuthorizationDecisionRequest;
import com.ixayda.iam.dto.IdentityAuthorizationInteractionResponse;
import com.ixayda.iam.dto.IdentityAuthorizationRedirectResponse;
import com.ixayda.iam.security.IdentityAuthorizationEndpoint;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = { "iam.protocol.issuer", "iam.protocol.identity-frontend-uri" })
@Tag(name = "protocol-interactions", description = "独立身份前端的同源交互接口。交互句柄与发起浏览器绑定，不能作为登录凭据；不接收原始协议参数或任意返回地址。")
@ApiResponse(responseCode = "400", description = "invalid_request：交互不属于当前浏览器、不可用或输入无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "401", description = "login_required：完成授权需要当前有效或重新建立的登录", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "403", description = "invalid_request：CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "405", description = "invalid_request：方法不受支持，Allow 声明支持的方法", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "413", description = "invalid_request：请求体超过 8192 字节", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "415", description = "invalid_request：完成交互需要 UTF-8 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "429", description = "temporarily_unavailable：入口限流", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
@ApiResponse(responseCode = "503", description = "server_error：存储、签发或必需审计不可用，不发布成功结果", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityProtocolError")))
public class IdentityAuthorizationController {

	private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
			.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
	private final IdentityAuthorizationEndpoint endpoint;

	IdentityAuthorizationController(IdentityAuthorizationEndpoint endpoint) { this.endpoint = endpoint; }

	@Operation(operationId = "getAuthorizationInteraction", summary = "查询本浏览器的待处理授权交互", description = "只返回客户端名称、原始 scope、到期时间及当前账号和交互提示。"
			+ "匿名浏览器可查看自己发起的交互；不接受查询串或请求体，不创建新会话。loginRequired 等提示只用于展示，完成时重新核对。"
			+ "句柄固定十分钟有效，最多八个未到期交互；前端应清理地址栏中的句柄，禁止持久化原始导航信息。")
	@GetMapping(path = "/api/authorization-interactions/{handle}", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityAuthorizationInteractionResponse find(@PathVariable String handle, HttpServletRequest request) {
		var view = this.endpoint.find(handle, request);
		return new IdentityAuthorizationInteractionResponse(view.clientId(), view.clientName(), view.scopes(), view.expiresAt(), view.subject(),
				view.loginRequired(), view.selectionRequired(), view.consentRequired());
	}

	@Operation(operationId = "completeAuthorizationInteraction", summary = "确认当前账号与范围或取消授权", description = "只接受 JSON decision=continue 或 cancel，不接受查询串、重复／额外字段或协议参数。"
			+ "先取得同一 Cookie 会话的 /api/csrf，登录成功后重新获取 CSRF；浏览器会话轮换保留交互归属。"
			+ "continue 代表明确选择当前账号并确认所展示的请求；需要重新登录时，先通过 JSON POST /login 建立新登录。"
			+ "cancel 不要求用户已登录，返回原登记回调的 access_denied。成功响应中的 redirectUri 由服务端生成，前端随后导航到该值。"
			+ "该值可能含一次性授权码，不得记录、持久化或转发给其他服务；接入应用比较 state 并在服务端使用原 PKCE verifier 兑换。"
			+ "单次消费、授权码及必需审计共同提交；响应丢失时重新发起应用登录，不重试完成请求。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityAuthorizationDecisionRequest.class)))
	@PostMapping(path = "/api/authorization-interactions/{handle}/complete", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityAuthorizationRedirectResponse complete(@PathVariable String handle, HttpServletRequest request) {
		var command = readDecision(request);
		return new IdentityAuthorizationRedirectResponse(this.endpoint.complete(handle, command.decision(), request));
	}

	@ExceptionHandler(IdentityAuthorizationEndpoint.Failure.class)
	void rejected(IdentityAuthorizationEndpoint.Failure failure, HttpServletResponse response) throws IOException { this.endpoint.writeFailure(response, failure); }

	@ExceptionHandler(IllegalArgumentException.class)
	void invalid(HttpServletRequest request, HttpServletResponse response) throws IOException { this.endpoint.writeFailure(response, this.endpoint.rejected(request, 400, "invalid_request")); }

	@ExceptionHandler(BodyTooLargeException.class)
	void tooLarge(HttpServletRequest request, HttpServletResponse response) throws IOException { this.endpoint.writeFailure(response, this.endpoint.rejected(request, 413, "invalid_request")); }

	private static IdentityAuthorizationDecisionRequest readDecision(HttpServletRequest request) {
		try {
			byte[] bytes = request.getInputStream().readNBytes(8193);
			if (bytes.length > 8192) { throw new BodyTooLargeException(); }
			String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(bytes)).toString();
			var body = JSON.readTree(text);
			if (body == null || !body.isObject() || body.size() != 1 || !body.path("decision").isString()
					|| !Set.of("continue", "cancel").contains(body.path("decision").asText())) { throw new IllegalArgumentException("Invalid authorization decision"); }
			return new IdentityAuthorizationDecisionRequest(body.path("decision").asText());
		}
		catch (JacksonException | IOException ex) { throw new IllegalArgumentException("Invalid authorization decision"); }
	}

	private static final class BodyTooLargeException extends RuntimeException { }

}
