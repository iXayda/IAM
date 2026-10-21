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

import com.ixayda.iam.dto.IdentityBrowserSessionPageResponse;
import com.ixayda.iam.dto.IdentityBrowserSessionResponse;
import com.ixayda.iam.dto.IdentityBrowserSessionSearchRequest;
import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.model.IdentityBrowserSessionPage;
import com.ixayda.iam.model.IdentityBrowserSessionSummary;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAccountSessions;
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
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
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
@RegisterReflectionForBinding({ IdentityBrowserSessionPageResponse.class, IdentityBrowserSessionResponse[].class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Tag(name = "account-sessions", description = "本人 IAM 浏览器会话管理；不代替独立应用授权管理及应用本地会话管理。")
@ApiResponse(responseCode = "400", description = "查询、路径或请求体无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "401", description = "当前密码会话失效或未登录", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "503", description = "持久化或必需审计不可用，不发布成功结果", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
public class IdentityAccountSessionController {

	private final IdentityAccountSessions sessions;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityAccountSessionController(IdentityAccountSessions sessions) { this.sessions = sessions; }

	@InitBinder("sessionSearch")
	void searchBinding(ExtendedServletRequestDataBinder binder) { binder.setDeclarativeBinding(true); binder.setHeaderPredicate(header -> false); }

	@Operation(operationId = "listCurrentBrowserSessions", summary = "分页查看本人的浏览器会话", description = "仅接受 pageSize 和 cursor 查询参数，无请求体。默认每页 20 条、最多 100 条；按创建时间和独立管理 UUID 排序，游标绑定当前用户。"
			+ "只返回当前凭据版本且尚在闲置及绝对期限内的认证会话；管理 UUID 不是 Cookie，也不能用于登录。过滤过期记录后可出现空页，仍须按 nextCursor 继续；跨页不是并发快照。"
			+ "current 标记本次调用者会话；列表不公开 IP、User-Agent、Cookie、CSRF、Token 或安全上下文。")
	@ApiResponse(responseCode = "200", description = "本人的有效浏览器会话页", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityBrowserSessionPageResponse.class)))
	@GetMapping(path = "/api/me/sessions", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> list(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@ParameterObject @ModelAttribute("sessionSearch") IdentityBrowserSessionSearchRequest query, HttpServletRequest request, HttpServletResponse response) throws IOException {
		requireNoBody(request);
		if (!Set.of("pageSize", "cursor").containsAll(request.getParameterMap().keySet()) || request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) { throw invalid(); }
		int pageSize = query.pageSize() == null ? 20 : query.pageSize(); var after = decodeCursor(query.cursor());
		if (pageSize < 1 || pageSize > 100 || after != null && !after.userId().equals(userId)) { throw invalid(); }
		var context = context(userId, request); if (context == null) { return invalidSession(request, response); }
		IdentityAccountSessions.Result<IdentityBrowserSessionPage> result;
		try { result = this.sessions.list(context, pageSize, after, save(response)); }
		catch (RuntimeException ex) { failed(request); throw ex; }
		if (result.outcome() == IdentityAccountSessions.Outcome.INVALID_SESSION) { return invalidSession(request, response); }
		return ResponseEntity.ok(new IdentityBrowserSessionPageResponse(result.value().items().stream().map(IdentityAccountSessionController::response).toList(), encodeCursor(result.value().nextCursor())));
	}

	@Operation(operationId = "revokeCurrentBrowserSession", summary = "撤销本人的指定浏览器会话", description = "提供列表中的独立管理 UUID；仅接受当前 Cookie 和同一会话 X-CSRF-TOKEN，无查询串或请求体。只在本人范围查找，缺失、已删除及他人会话统一 404。"
			+ "撤销当前会话时清除 IAM 登录状态；撤销其他会话保留当前登录。已签发应用授权及其刷新家族保持独立；尚未兑换的授权码仍须有效源浏览器会话，源会话结束后不可兑换。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "指定浏览器会话已撤销；当前会话被撤销时 Cookie 清除", content = @Content)
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或不属于当前会话", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "本人没有此浏览器会话", content = @Content)
	@PostMapping("/api/me/sessions/{sessionId}/revoke")
	public ResponseEntity<?> revoke(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId, @PathVariable String sessionId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		requireNoBody(request); if (request.getQueryString() != null) { throw invalid(); } var id = id(sessionId);
		var context = context(userId, request); if (context == null) { return invalidSession(request, response); }
		IdentityAccountSessions.Result<Boolean> result;
		try { result = this.sessions.revoke(context, id, save(response)); }
		catch (RuntimeException ex) { failed(request); throw ex; }
		if (result.outcome() == IdentityAccountSessions.Outcome.INVALID_SESSION) { return invalidSession(request, response); }
		if (result.outcome() == IdentityAccountSessions.Outcome.NOT_FOUND) { return ResponseEntity.notFound().build(); }
		if (Boolean.TRUE.equals(result.value())) { SecurityContextHolder.clearContext(); this.logout.logout(request, response, null); }
		return ResponseEntity.noContent().build();
	}

	@Operation(operationId = "revokeAllCurrentSessions", summary = "撤销本人的全部会话和应用授权", description = "仅接受当前 Cookie 和同一会话 X-CSRF-TOKEN，无查询串或请求体。不受列表分页影响，结束全部 IAM 浏览器会话、未兑换授权码、已签发应用授权及刷新家族。"
			+ "使已验证但尚未保存的旧登录证据失效；账号保持启用，密码不变，可以重新登录。提交成功后清除当前 Cookie。应用须执行在线校验；纯离线验签仍受 Token 剩余有效期约束，IAM 不直接删除应用本地会话。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "全部下线已提交，当前 Cookie 清除", content = @Content)
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或不属于当前会话", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping("/api/me/sessions/revoke-all")
	public ResponseEntity<?> revokeAll(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		requireNoBody(request); if (request.getQueryString() != null) { throw invalid(); }
		var context = context(userId, request); if (context == null) { return invalidSession(request, response); }
		IdentityAccountSessions.Result<Void> result;
		try { result = this.sessions.revokeAll(context, save(response)); }
		catch (RuntimeException ex) { failed(request); throw ex; }
		if (result.outcome() == IdentityAccountSessions.Outcome.INVALID_SESSION) { return invalidSession(request, response); }
		SecurityContextHolder.clearContext(); this.logout.logout(request, response, null);
		return ResponseEntity.noContent().build();
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
	private ResponseEntity<?> invalidSession(HttpServletRequest request, HttpServletResponse response) { SecurityContextHolder.clearContext(); this.logout.logout(request, response, null); return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED); }
	private static Runnable save(HttpServletResponse response) { return () -> { try { response.flushBuffer(); } catch (IOException ex) { throw new UncheckedIOException(ex); } }; }
	private static UUID id(String value) { var id = UUID.fromString(value); if (!id.toString().equals(value)) { throw invalid(); } return id; }
	private static IdentityBrowserSessionResponse response(IdentityBrowserSessionSummary value) {
		return new IdentityBrowserSessionResponse(value.id(), value.createdAt(), value.authenticatedAt(), value.lastAccessedAt(), value.idleExpiresAt(), value.absoluteExpiresAt(), value.current());
	}
	private static String encodeCursor(IdentityBrowserSessionPage.Cursor cursor) {
		if (cursor == null) { return null; }
		return Base64.getUrlEncoder().withoutPadding().encodeToString(("1\n" + cursor.userId() + "\n" + cursor.createdAt() + "\n" + cursor.id()).getBytes(StandardCharsets.UTF_8));
	}
	private static IdentityBrowserSessionPage.Cursor decodeCursor(String value) {
		if (value == null) { return null; } if (value.isEmpty() || value.length() > 512) { throw invalid(); }
		byte[] bytes = Base64.getUrlDecoder().decode(value); String text = new String(bytes, StandardCharsets.UTF_8); String[] parts = text.split("\n", -1);
		if (parts.length != 4 || !parts[0].equals("1") || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8)) || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) { throw invalid(); }
		try { return new IdentityBrowserSessionPage.Cursor(id(parts[1]), Instant.parse(parts[2]), id(parts[3])); }
		catch (DateTimeException ex) { throw invalid(); }
	}
	private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid account session request"); }
	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<?> invalidSessionRequest() { return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.BAD_REQUEST); }
}
