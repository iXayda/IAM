package com.ixayda.iam.controller;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.dto.IdentityResourceCreateRequest;
import com.ixayda.iam.dto.IdentityResourceNameRequest;
import com.ixayda.iam.dto.IdentityResourcePageResponse;
import com.ixayda.iam.dto.IdentityResourceResponse;
import com.ixayda.iam.dto.IdentityResourceSearchRequest;
import com.ixayda.iam.dto.IdentityResourceStateRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourcePage;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityResourceManagement;
import com.ixayda.iam.service.IdentityResources;

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
@RegisterReflectionForBinding(IdentityResourceResponse[].class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Tag(name = "resources", description = "需要当前管理员资格及有效的密码和 TOTP 管理会话。写操作携带本次操作的新 TOTP，不延长已有认证期限。")
@ApiResponse(responseCode = "400", description = "输入、TOTP 或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
public class IdentityResourceController {

	private final IdentityResources resources;
	private final IdentityResourceManagement management;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityResourceController(IdentityResources resources, IdentityResourceManagement management, IdentityAdministratorSessions administrators) {
		this.resources = resources;
		this.management = management;
		this.administrators = administrators;
	}

	@InitBinder({ "resourceSearch", "resourceCreation", "resourceName", "resourceState" })
	void resourceBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "searchResources", summary = "查询资源列表", description = "仅接受 status、pageSize、cursor，不接受请求体或重复参数。每页 1 至 100 条，默认 20，按创建时间和 UUID 升序。nextCursor 为 null 时结束，翻页保持状态筛选相同。")
	@GetMapping(path = "/api/admin/resources", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityResourcePageResponse search(@org.springdoc.core.annotations.ParameterObject @ModelAttribute("resourceSearch") IdentityResourceSearchRequest query, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of("status", "pageSize", "cursor"), "Invalid resource query");
		if ((request.getParameter("pageSize") != null && (query.pageSize() == null || !query.pageSize().toString().equals(request.getParameter("pageSize"))))
				|| (request.getParameter("status") != null && (query.status() == null || !query.status().name().equals(request.getParameter("status"))))) {
			throw new IllegalArgumentException("Invalid resource query");
		}
		var page = this.resources.search(query.status(), query.pageSize() == null ? 20 : query.pageSize(), decodeCursor(query.cursor()));
		return new IdentityResourcePageResponse(page.items().stream().map(IdentityResourceController::response).toList(), encodeCursor(page.nextCursor()));
	}

	@Operation(operationId = "getResource", summary = "查询指定资源", description = "resourceId 为完整 UUID；不接受查询参数或请求体。不返回客户端、角色、在线校验凭据或授权状态。")
	@ApiResponse(responseCode = "404", description = "资源不存在", content = @Content)
	@GetMapping(path = "/api/admin/resources/{resourceId}", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<IdentityResourceResponse> find(@PathVariable String resourceId, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of(), "Invalid resource query");
		return this.resources.findById(parseId(resourceId)).map(IdentityResourceController::response)
				.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
	}

	@Operation(operationId = "createResource", summary = "创建应用资源", description = "需要本次操作的新 TOTP。audience 精确匹配、区分大小写，创建后不可修改或复用。仅接受 audience、displayName、code 及 CSRF 表单字段，不接受查询参数、额外或重复字段。与成功审计和当前会话原子提交。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也接受 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "201", description = "已创建资源", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceResponse.class)))
	@ApiResponse(responseCode = "409", description = "Audience 已存在", content = @Content(mediaType = "text/plain"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityResourceCreateRequest.class)))
	@ApiResponse(responseCode = "415", description = "写操作需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/resources", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> create(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId,
			@Parameter(hidden = true) @ModelAttribute("resourceCreation") IdentityResourceCreateRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return execute(actorId, "browser:admin-resource-create", request, response,
				context -> this.management.create(context, command.audience(), command.displayName(), command.code(), save(response)), true);
	}

	@ApiResponse(responseCode = "200", description = "资源当前状态", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceResponse.class)))
	@Operation(operationId = "updateResourceName", summary = "修改资源显示名", description = "需要本次操作的新 TOTP，携带最近查询到的正整数 version。仅接受 version、displayName、code 和 CSRF；不接受查询参数。实际改名撤销原始绑定到该资源的全部应用授权。版本过期返回 409，不修改资源或消费验证码；无变化操作保持版本但消费本次验证码。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "404", description = "资源不存在；仅在本次 TOTP 验证后返回", content = @Content)
	@ApiResponse(responseCode = "409", description = "版本冲突", content = @Content(mediaType = "text/plain"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityResourceNameRequest.class)))
	@ApiResponse(responseCode = "415", description = "写操作需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/resources/{resourceId}/name", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> updateDisplayName(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String resourceId,
			@Parameter(hidden = true) @ModelAttribute("resourceName") IdentityResourceNameRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = parseId(resourceId);
		return execute(actorId, "browser:admin-resource-name", request, response,
				context -> this.management.updateDisplayName(context, id, version(command.version()), command.displayName(), command.code(), save(response)), false);
	}

	@ApiResponse(responseCode = "200", description = "资源当前状态", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceResponse.class)))
	@Operation(operationId = "disableResource", summary = "禁用资源", description = "需要本次操作的新 TOTP 和最近查询到的正整数 version。仅接受 version、code 和 CSRF；不接受查询参数。实际禁用撤销原始绑定到该资源的全部应用授权，保留不可变资源身份。无变化操作保持版本，但消费验证码。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "404", description = "资源不存在；仅在本次 TOTP 验证后返回", content = @Content)
	@ApiResponse(responseCode = "409", description = "版本冲突", content = @Content(mediaType = "text/plain"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityResourceStateRequest.class)))
	@ApiResponse(responseCode = "415", description = "写操作需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/resources/{resourceId}/disable", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> disable(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String resourceId,
			@Parameter(hidden = true) @ModelAttribute("resourceState") IdentityResourceStateRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return setEnabled(actorId, resourceId, command, false, request, response);
	}

	@ApiResponse(responseCode = "200", description = "资源当前状态", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityResourceResponse.class)))
	@Operation(operationId = "enableResource", summary = "启用资源", description = "需要本次操作的新 TOTP 和最近查询到的正整数 version。仅接受 version、code 和 CSRF；不接受查询参数。实际启用撤销旧应用授权，不重新创建身份或恢复已撤销授权。无变化操作保持版本，但消费验证码。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "404", description = "资源不存在；仅在本次 TOTP 验证后返回", content = @Content)
	@ApiResponse(responseCode = "409", description = "版本冲突", content = @Content(mediaType = "text/plain"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityResourceStateRequest.class)))
	@ApiResponse(responseCode = "415", description = "写操作需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/resources/{resourceId}/enable", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> enable(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String resourceId,
			@Parameter(hidden = true) @ModelAttribute("resourceState") IdentityResourceStateRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return setEnabled(actorId, resourceId, command, true, request, response);
	}

	private ResponseEntity<?> setEnabled(UUID actorId, String resourceId, IdentityResourceStateRequest command,
			boolean enabled, HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = parseId(resourceId);
		return execute(actorId, enabled ? "browser:admin-resource-enable" : "browser:admin-resource-disable", request, response,
				context -> this.management.setEnabled(context, id, version(command.version()), enabled, command.code(), save(response)), false);
	}

	private ResponseEntity<?> execute(UUID actorId, String source, HttpServletRequest request, HttpServletResponse response,
			Function<IdentityAdministratorContext, IdentityResourceManagement.Result> operation, boolean creation) throws IOException {
		UUID correlation = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlation, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var evidence = stored instanceof IdentityAdministratorAuthentication current ? current : null;
		var context = new IdentityAdministratorContext(actorId, session.getId(), version, authenticatedAt, evidence,
				new TotpAuthenticationContext(source, InetAddress.getByName(request.getRemoteAddr()), correlation));
		IdentityResourceManagement.Result result;
		try { result = operation.apply(context); }
		catch (RuntimeException ex) {
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
		return switch (result.status()) {
			case COMPLETED -> creation
					? ResponseEntity.created(URI.create(request.getContextPath() + "/api/admin/resources/" + result.resource().id())).body(response(result.resource()))
					: ResponseEntity.ok(response(result.resource()));
			case INVALID_SESSION -> invalidSession(actorId, correlation, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case CONFLICT -> ResponseEntity.status(409).contentType(MediaType.TEXT_PLAIN).body("Resource conflict");
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case INVALID_INPUT, REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Resource operation rejected");
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(actorId, correlationId);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private static Runnable save(HttpServletResponse response) {
		return () -> {
			try { response.flushBuffer(); }
			catch (IOException ex) { throw new UncheckedIOException(ex); }
		};
	}

	private static long version(Long value) { return value == null ? 0 : value; }

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidResourceRequest() {
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid resource request");
	}

	private static UUID parseId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) { throw new IllegalArgumentException("Invalid resource id"); }
		return id;
	}

	private static IdentityResourceResponse response(IdentityResource resource) {
		return new IdentityResourceResponse(resource.id(), resource.audience(), resource.displayName(), resource.status(),
				resource.version(), resource.createdAt(), resource.updatedAt());
	}

	private static String encodeCursor(IdentityResourcePage.Cursor cursor) {
		if (cursor == null) { return null; }
		String value = "1\n" + cursor.createdAt() + "\n" + cursor.id() + "\n" + (cursor.status() == null ? "" : cursor.status().name());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
	}

	private static IdentityResourcePage.Cursor decodeCursor(String value) {
		if (value == null) { return null; }
		if (value.isEmpty() || value.length() > 512) { throw new IllegalArgumentException("Invalid resource cursor"); }
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		String text = new String(bytes, StandardCharsets.UTF_8);
		String[] parts = text.split("\n", -1);
		if (parts.length != 4 || !parts[0].equals("1") || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
			throw new IllegalArgumentException("Invalid resource cursor");
		}
		try { return new IdentityResourcePage.Cursor(Instant.parse(parts[1]), parseId(parts[2]), parts[3].isEmpty() ? null : IdentityResource.Status.valueOf(parts[3])); }
		catch (DateTimeException ex) { throw new IllegalArgumentException("Invalid resource cursor", ex); }
	}
}
