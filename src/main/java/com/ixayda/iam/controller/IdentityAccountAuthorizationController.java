package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityAuthorizationPageResponse;
import com.ixayda.iam.dto.IdentityAuthorizationResponse;
import com.ixayda.iam.dto.IdentityAuthorizationSearchRequest;
import com.ixayda.iam.model.IdentityAuthorizationPage;
import com.ixayda.iam.model.IdentityAuthorizationSummary;
import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAccountAuthorizations;
import com.ixayda.iam.service.IdentityBrowserSessions;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Tag(name = "account-authorizations", description = "本人应用授权，与 IAM 浏览器会话及应用本地会话分别管理；仅接受当前密码登录会话，不接受业务 Bearer Token。")
@ApiResponse(responseCode = "400", description = "查询、路径或请求体无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "401", description = "未登录或当前密码会话失效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "503", description = "授权、会话或必需审计不可用，未发布成功结果", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
public class IdentityAccountAuthorizationController {

	private final IdentityAccountAuthorizations authorizations;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityAccountAuthorizationController(IdentityAccountAuthorizations authorizations) { this.authorizations = authorizations; }

	@InitBinder("authorizationSearch")
	void searchBinding(ExtendedServletRequestDataBinder binder) { binder.setDeclarativeBinding(true); binder.setHeaderPredicate(header -> false); }

	@GetMapping(path = "/api/me/authorizations", produces = MediaType.APPLICATION_JSON_VALUE)
	@Operation(operationId = "listCurrentAuthorizations", summary = "分页查看本人应用授权", description = "按签发时间和授权 UUID 升序返回每页至多 100 条记录，默认 20；游标绑定当前用户。仅接受 pageSize 和 cursor 查询参数，无请求体。"
			+ "返回原始资源归属、当前名称、实际 scope 及记录状态，不返回 Token、秘密或浏览器 Cookie。名称是展示资料，状态不代替在线校验或业务应用会话状态；并发变更期间列表不是跨页快照。")
	@ApiResponse(responseCode = "200", description = "本人的授权记录页", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityAuthorizationPageResponse.class)))
	public ResponseEntity<?> list(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@ParameterObject @ModelAttribute("authorizationSearch") IdentityAuthorizationSearchRequest query,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		requireNoBody(request);
		if (!Set.of("pageSize", "cursor").containsAll(request.getParameterMap().keySet()) || request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) { throw invalid(); }
		var context = context(userId, request); if (context == null) { return invalidSession(request, response); }
		int pageSize = query.pageSize() == null ? 20 : query.pageSize(); var after = decodeCursor(query.cursor());
		if (pageSize < 1 || pageSize > 100 || after != null && !after.userId().equals(userId)) { throw invalid(); }
		IdentityAccountAuthorizations.Result<IdentityAuthorizationPage> result;
		try { result = this.authorizations.list(context, pageSize, after, save(response)); }
		catch (RuntimeException ex) { failed(request); throw ex; }
		if (result.outcome() == IdentityAccountAuthorizations.Outcome.INVALID_SESSION) { return invalidSession(request, response); }
		return ResponseEntity.ok(new IdentityAuthorizationPageResponse(result.value().items().stream().map(IdentityAccountAuthorizationController::response).toList(), encodeCursor(result.value().nextCursor())));
	}

	@PostMapping("/api/me/authorizations/{authorizationId}/revoke")
	@Operation(operationId = "revokeCurrentAuthorization", summary = "撤销本人的指定应用授权", description = "仅接受当前 Cookie、同一会话 X-CSRF-TOKEN 及授权 UUID；无查询串或请求体。只在当前用户范围内查找，缺失和他人授权统一 404。"
			+ "撤销全部原生 Token、未兑换授权码及对应刷新家族，重复撤销保持终态且不新增变更审计。保留 IAM 浏览器登录和其他应用授权。"
			+ "在线资源最多受已确认的 5 秒正缓存影响；应用服务端须执行在线校验与业务权限检查，并在失效时清理本地会话。操作不会直接删除应用的 Cookie。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "授权已撤销或原已撤销", content = @Content)
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或不属于当前会话", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "当前用户没有此授权，不回显外部标识", content = @Content)
	public ResponseEntity<?> revoke(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId, @PathVariable String authorizationId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		requireNoBody(request); if (request.getQueryString() != null) { throw invalid(); } var id = id(authorizationId);
		var context = context(userId, request); if (context == null) { return invalidSession(request, response); }
		IdentityAccountAuthorizations.Result<Boolean> result;
		try { result = this.authorizations.revoke(context, id, save(response)); }
		catch (RuntimeException ex) { failed(request); throw ex; }
		return switch (result.outcome()) {
			case INVALID_SESSION -> invalidSession(request, response);
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case COMPLETED -> ResponseEntity.noContent().build();
		};
	}

	private static IdentityBrowserContext context(UUID userId, HttpServletRequest request) {
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)
				|| !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)) { return null; }
		return new IdentityBrowserContext(userId, session.getId(), authenticatedAt, version, UUID.randomUUID());
	}

	private static void requireNoBody(HttpServletRequest request) throws IOException {
		if (request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null || request.getInputStream().read() != -1) { throw invalid(); }
	}
	private static void failed(HttpServletRequest request) { var session = request.getSession(false); if (session != null) { session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true); } }
	private ResponseEntity<?> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext(); this.logout.logout(request, response, null); return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}
	private static Runnable save(HttpServletResponse response) { return () -> { try { response.flushBuffer(); } catch (IOException ex) { throw new UncheckedIOException(ex); } }; }
	private static UUID id(String value) { var id = UUID.fromString(value); if (!id.toString().equals(value)) { throw invalid(); } return id; }
	private static IdentityAuthorizationResponse response(IdentityAuthorizationSummary value) {
		return new IdentityAuthorizationResponse(value.id(), value.clientId(), value.clientName(), value.resourceId(), value.resourceName(), value.audience(), value.issuedAt(), value.expiresAt(), value.scopes(), value.status());
	}
	private static String encodeCursor(IdentityAuthorizationPage.Cursor value) {
		if (value == null) { return null; }
		return Base64.getUrlEncoder().withoutPadding().encodeToString(("1\n" + value.userId() + "\n" + value.issuedAt() + "\n" + value.id()).getBytes(StandardCharsets.UTF_8));
	}
	private static IdentityAuthorizationPage.Cursor decodeCursor(String value) {
		if (value == null) { return null; } if (value.isEmpty() || value.length() > 512) { throw invalid(); }
		byte[] bytes = Base64.getUrlDecoder().decode(value); String text = new String(bytes, StandardCharsets.UTF_8); String[] parts = text.split("\n", -1);
		if (parts.length != 4 || !parts[0].equals("1") || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) { throw invalid(); }
		try { return new IdentityAuthorizationPage.Cursor(id(parts[1]), Instant.parse(parts[2]), id(parts[3])); }
		catch (DateTimeException ex) { throw invalid(); }
	}
	private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid account authorization request"); }
	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<?> invalidAuthorizationRequest() { return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.BAD_REQUEST); }
}
