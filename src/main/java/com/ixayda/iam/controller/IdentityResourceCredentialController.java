package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.dto.IdentityResourceCredentialChangeRequest;
import com.ixayda.iam.dto.IdentityResourceCredentialResponse;
import com.ixayda.iam.dto.IdentityResourceSecretResponse;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResourceCredential;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityResourceCredentialManagement;
import com.ixayda.iam.service.IdentityResourceCredentials;

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

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RegisterReflectionForBinding(IdentityResourceSecretResponse.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Tag(name = "resource-credentials", description = "单资源在线校验身份，与应用客户端秘密隔离。需要当前管理员密码及 TOTP 会话；写操作另需本次新 TOTP。")
@ApiResponse(responseCode = "400", description = "输入或 TOTP 无效；仅接受 UTF-8 JSON 整数 version 和文本 code，不接受额外、重复字段或查询串", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "401", description = "当前登录已失效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "404", description = "资源或凭据不存在；写操作仅在本次 TOTP 验证后返回", content = @Content)
@ApiResponse(responseCode = "409", description = "凭据版本变化，或资源禁用期间请求新凭据", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string")))
@ApiResponse(responseCode = "413", description = "正文超过 8192 字节", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "415", description = "写操作需要 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "429", description = "入口或新 TOTP 限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "503", description = "持久化或必需审计不可用，不发布秘密或成功结果", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
public class IdentityResourceCredentialController {

	private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
			.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
	private final IdentityResourceCredentials credentials;
	private final IdentityResourceCredentialManagement management;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityResourceCredentialController(IdentityResourceCredentials credentials, IdentityResourceCredentialManagement management, IdentityAdministratorSessions administrators) {
		this.credentials = credentials; this.management = management; this.administrators = administrators;
	}

	@Operation(operationId = "getResourceCredential", summary = "查询资源校验凭据状态", description = "只返回资源 UUID、状态、独立凭据版本及时间；不返回秘密或摘要。不接受查询串或正文；未创建凭据返回 404，此时首次轮换使用 version=0。")
	@GetMapping(path = "/api/admin/resources/{resourceId}/validation-credential", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityResourceCredentialResponse find(@PathVariable String resourceId, HttpServletRequest request) throws IOException {
		if (request.getQueryString() != null || request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null
				|| request.getInputStream().read() != -1) { throw invalid(); }
		return response(this.credentials.findByResourceId(id(resourceId)).orElseThrow(() -> new NoSuchElementException("Resource credential not found")));
	}

	@Operation(operationId = "rotateResourceCredential", summary = "创建或轮换资源校验凭据", description = "version=0 首次创建；已有凭据提供最近版本及本次新 TOTP code。资源须启用。新秘密只在成功提交后的本次响应交付，立即使旧秘密失效；显式禁用过的凭据也通过新秘密重新启用。"
			+ "保存于对应资源服务端的秘密管理设施，不交给业务应用浏览器端或作为应用客户端秘密。管理前端仅本次展示，关闭交付视图即清理内存；响应丢失后再次轮换，不重试旧版本。秘密更新不更改应用授权；资源停用与凭据显式禁用独立。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceCredentialChangeRequest.class)))
	@ApiResponse(responseCode = "200", description = "当前凭据及仅本次交付的新秘密", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceSecretResponse.class)))
	@PostMapping(path = "/api/admin/resources/{resourceId}/validation-credential/rotate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> rotateSecret(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String resourceId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = id(resourceId); var command = command(request);
		return complete(actorId, "rotate", request, response,
				context -> this.management.rotateSecret(context, id, command.version(), command.code(), save(response)));
	}

	@Operation(operationId = "disableResourceCredential", summary = "禁用资源校验凭据", description = "提供最近正整数凭据 version 及本次新 TOTP code。保留摘要及轮换时间，旧秘密不可重新启用；重复禁用仍消费 TOTP，但保持版本和变更审计。版本冲突或目标缺失回滚本次验证码消费。应用授权不随校验身份禁用而撤销。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceCredentialChangeRequest.class)))
	@ApiResponse(responseCode = "200", description = "当前凭据公开状态及版本，不返回秘密", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceCredentialResponse.class)))
	@PostMapping(path = "/api/admin/resources/{resourceId}/validation-credential/disable", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> disable(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String resourceId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = id(resourceId); var command = command(request);
		if (command.version() < 1) { throw invalid(); }
		return complete(actorId, "disable", request, response,
				context -> this.management.disable(context, id, command.version(), command.code(), save(response)));
	}

	private ResponseEntity<?> complete(UUID actorId, String action, HttpServletRequest request, HttpServletResponse response,
			Function<IdentityAdministratorContext, IdentityResourceCredentialManagement.Result> operation) throws IOException {
		UUID correlation = UUID.randomUUID(); var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlation, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var evidence = stored instanceof IdentityAdministratorAuthentication current ? current : null;
		var context = new IdentityAdministratorContext(actorId, session.getId(), version, authenticatedAt, evidence,
				new TotpAuthenticationContext("browser:admin-resource-credential-" + action, InetAddress.getByName(request.getRemoteAddr()), correlation));
		IdentityResourceCredentialManagement.Result result;
		try { result = operation.apply(context); }
		catch (RuntimeException ex) { session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true); throw ex; }
		return switch (result.status()) {
			case COMPLETED -> ResponseEntity.ok(result.secret() == null ? response(result.credential()) : new IdentityResourceSecretResponse(response(result.credential()), result.secret()));
			case INVALID_SESSION -> invalidSession(actorId, correlation, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case CONFLICT -> ResponseEntity.status(409).contentType(MediaType.TEXT_PLAIN).body("Resource credential conflict");
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case INVALID_INPUT, REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Resource credential operation rejected");
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlation, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext(); this.logout.logout(request, response, null); this.administrators.recordAccessDenied(actorId, correlation);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private static IdentityResourceCredentialResponse response(IdentityResourceCredential credential) {
		return new IdentityResourceCredentialResponse(credential.resourceId(), credential.status(), credential.version(), credential.createdAt(), credential.rotatedAt(), credential.updatedAt());
	}

	private static IdentityResourceCredentialChangeRequest command(HttpServletRequest request) {
		if (request.getQueryString() != null) { throw invalid(); }
		var charset = MediaType.parseMediaType(request.getContentType()).getCharset();
		if (charset != null && !StandardCharsets.UTF_8.equals(charset)) { throw invalid(); }
		try {
			byte[] bytes = request.getInputStream().readNBytes(8193); if (bytes.length > 8192) { throw new BodyTooLargeException(); }
			String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
			var body = JSON.readTree(text);
			if (body == null || !body.isObject() || body.size() != 2 || !Set.of("version", "code").containsAll(body.propertyNames())
					|| !body.path("version").isIntegralNumber() || !body.path("version").canConvertToLong() || body.path("version").longValue() < 0
					|| !body.path("code").isString()) { throw invalid(); }
			return new IdentityResourceCredentialChangeRequest(body.path("version").longValue(), body.path("code").asText());
		}
		catch (JacksonException | IOException ex) { throw invalid(); }
	}

	private static UUID id(String value) {
		UUID id = UUID.fromString(value); if (!id.toString().equalsIgnoreCase(value)) { throw invalid(); } return id;
	}
	private static Runnable save(HttpServletResponse response) { return () -> { try { response.flushBuffer(); } catch (IOException ex) { throw new UncheckedIOException(ex); } }; }
	private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid resource credential request"); }

	@ExceptionHandler(NoSuchElementException.class)
	ResponseEntity<Void> missingCredential() { return ResponseEntity.notFound().build(); }
	@ExceptionHandler(IllegalArgumentException.class)
	ResponseEntity<String> invalidCredentialRequest() { return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid resource credential request"); }
	@ExceptionHandler(BodyTooLargeException.class)
	ResponseEntity<?> credentialBodyTooLarge() { return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.PAYLOAD_TOO_LARGE); }
	private static final class BodyTooLargeException extends RuntimeException { }

}
