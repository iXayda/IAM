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
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.dto.IdentityClientChangeRequest;
import com.ixayda.iam.dto.IdentityClientConfigurationRequest;
import com.ixayda.iam.dto.IdentityClientConfigurationResponse;
import com.ixayda.iam.dto.IdentityClientCreateRequest;
import com.ixayda.iam.dto.IdentityClientPageResponse;
import com.ixayda.iam.dto.IdentityClientResponse;
import com.ixayda.iam.dto.IdentityClientSearchRequest;
import com.ixayda.iam.dto.IdentityClientSecretResponse;
import com.ixayda.iam.dto.IdentityClientSummaryResponse;
import com.ixayda.iam.dto.IdentityClientUpdateRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.IdentityClientPage;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityClientManagement;
import com.ixayda.iam.service.IdentityClients;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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
@Tag(name = "clients", description = "保密 Web/BFF 客户端管理。需要当前管理员资格及密码和 TOTP 管理会话；写操作另携带本次新 TOTP。创建或轮换秘密仅在该次成功响应中交付。")
@ApiResponse(responseCode = "400", description = "输入或 TOTP 无效；JSON 字段须完整且无重复，不进行类型转换", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "401", description = "登录已失效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "403", description = "管理资格、MFA 或 CSRF 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "404", description = "客户端、资源或角色不存在", content = @Content)
@ApiResponse(responseCode = "409", description = "版本变化或当前资源、角色状态不允许该操作", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string")))
@ApiResponse(responseCode = "413", description = "请求体超过 8192 字节", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
@ApiResponse(responseCode = "429", description = "TOTP 验证或入口限流", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
@ApiResponse(responseCode = "503", description = "持久化或必需审计不可用，未发布成功结果", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
public class IdentityClientController {

	private final IdentityClients clients;
	private final IdentityClientManagement management;
	private final IdentityAdministratorSessions administrators;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityClientController(IdentityClients clients, IdentityClientManagement management, IdentityAdministratorSessions administrators) {
		this.clients = clients;
		this.management = management;
		this.administrators = administrators;
	}

	@InitBinder("clientSearch")
	void clientQueryBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "searchClients", summary = "分页查询客户端摘要", description = "仅接受 status、pageSize、cursor，无请求体或重复字段。每页 1 至 100，默认 20，按创建时间和 UUID 升序。nextCursor 为 null 时结束；游标不能改变状态筛选，跨页不固定快照。完整配置通过详情查询。")
	@GetMapping(path = "/api/admin/clients", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityClientPageResponse search(@org.springdoc.core.annotations.ParameterObject @ModelAttribute("clientSearch") IdentityClientSearchRequest query,
			HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of("status", "pageSize", "cursor"), "Invalid client query");
		if ((request.getParameter("pageSize") != null && (query.pageSize() == null || !query.pageSize().toString().equals(request.getParameter("pageSize"))))
				|| (request.getParameter("status") != null && (query.status() == null || !query.status().name().equals(request.getParameter("status"))))) {
			throw new IllegalArgumentException("Invalid client query");
		}
		var page = this.clients.search(query.status(), query.pageSize() == null ? 20 : query.pageSize(), decodeCursor(query.cursor()));
		return new IdentityClientPageResponse(page.items().stream().map(client -> new IdentityClientSummaryResponse(client.id(), client.configuration().displayName(),
				client.configuration().resourceId(), client.status(), client.version(), client.createdAt(), client.updatedAt(), client.secretRotatedAt())).toList(), encodeCursor(page.nextCursor()));
	}

	@Operation(operationId = "getClient", summary = "查询客户端公开配置", description = "返回配置、启用状态和版本；不返回秘密、秘密哈希或框架内部设置。不接受查询参数或请求体。")
	@GetMapping(path = "/api/admin/clients/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityClientResponse find(@PathVariable String clientId, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of(), "Invalid client query");
		return response(this.clients.findById(IdentityClientRequests.id(clientId)).orElseThrow(() -> new NoSuchElementException("Client not found")));
	}

	@Operation(operationId = "createClient", summary = "创建保密客户端并交付秘密", description = "JSON 完整提供 configuration 与新 TOTP code；不接受查询参数。秘密仅本次交付，应保存于应用服务端的秘密管理设施；响应丢失时轮换后重新交付。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, description = "同一会话的 /api/csrf 令牌", schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientCreateRequest.class)))
	@ApiResponse(responseCode = "201", description = "客户端已创建，Location 指向详情；secret 仅本次交付", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientSecretResponse.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/clients", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> create(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, HttpServletRequest request, HttpServletResponse response) throws IOException {
		var command = IdentityClientRequests.create(request);
		return complete(actorId, "create", true, request, response,
				context -> this.management.create(context, configuration(command.configuration()), command.code(), save(response)));
	}

	@Operation(operationId = "updateClientConfiguration", summary = "替换客户端配置", description = "JSON 完整提供 configuration、最近版本 version 与本次新 TOTP code。实际变更同时撤销该客户端全部应用授权。相同配置仍消费 TOTP，保持版本和变更审计不变；目标缺失、版本或配置冲突回滚本次 TOTP 消费。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientUpdateRequest.class)))
	@ApiResponse(responseCode = "200", description = "当前客户端公开配置及版本", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientResponse.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/clients/{clientId}/configuration", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> updateConfiguration(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String clientId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = IdentityClientRequests.id(clientId);
		var command = IdentityClientRequests.update(request);
		return complete(actorId, "update", false, request, response,
				context -> this.management.updateConfiguration(context, id, command.version(), configuration(command.configuration()), command.code(), save(response)));
	}

	@Operation(operationId = "disableClient", summary = "禁用客户端", description = "JSON 提供最近版本 version 与本次新 TOTP code；实际禁用同时撤销该客户端全部应用授权；重复禁用仍消费 TOTP，保持版本和变更审计不变。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientChangeRequest.class)))
	@ApiResponse(responseCode = "200", description = "当前客户端公开配置及版本", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientResponse.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/clients/{clientId}/disable", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> disable(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String clientId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return setEnabled(actorId, IdentityClientRequests.id(clientId), false, IdentityClientRequests.change(request), request, response);
	}

	@Operation(operationId = "enableClient", summary = "启用客户端", description = "JSON 提供最近版本 version 与本次新 TOTP code，所属资源必须启用。实际启用撤销旧应用授权；重复启用仍消费 TOTP，保持版本和变更审计不变。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientChangeRequest.class)))
	@ApiResponse(responseCode = "200", description = "当前客户端公开配置及版本", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientResponse.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/clients/{clientId}/enable", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> enable(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String clientId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return setEnabled(actorId, IdentityClientRequests.id(clientId), true, IdentityClientRequests.change(request), request, response);
	}

	@Operation(operationId = "rotateClientSecret", summary = "轮换并交付客户端秘密", description = "JSON 提供最近版本 version 与本次新 TOTP code。立即替换旧秘密并撤销该客户端全部应用授权，仅本次响应交付新秘密；不改变客户端标识，也不自动启用禁用客户端。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, required = true, schema = @Schema(type = "string"))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientChangeRequest.class)))
	@ApiResponse(responseCode = "200", description = "当前客户端与仅本次交付的新秘密", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityClientSecretResponse.class)))
	@ApiResponse(responseCode = "415", description = "需要 application/json", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@PostMapping(path = "/api/admin/clients/{clientId}/secret/rotate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> rotateSecret(@Parameter(hidden = true) @AuthenticationPrincipal UUID actorId, @PathVariable String clientId,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		UUID id = IdentityClientRequests.id(clientId);
		var command = IdentityClientRequests.change(request);
		return complete(actorId, "secret-rotate", false, request, response,
				context -> this.management.rotateSecret(context, id, command.version(), command.code(), save(response)));
	}

	private ResponseEntity<?> setEnabled(UUID actorId, UUID id, boolean enabled, IdentityClientChangeRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		return complete(actorId, enabled ? "enable" : "disable", false, request, response,
				context -> this.management.setEnabled(context, id, command.version(), enabled, command.code(), save(response)));
	}

	private ResponseEntity<?> complete(UUID actorId, String action, boolean created, HttpServletRequest request, HttpServletResponse response,
			Function<IdentityAdministratorContext, IdentityClientManagement.Result> operation) throws IOException {
		UUID correlation = UUID.randomUUID();
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(actorId, correlation, request, response);
		}
		Object stored = session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION);
		var evidence = stored instanceof IdentityAdministratorAuthentication current ? current : null;
		var context = new IdentityAdministratorContext(actorId, session.getId(), version, authenticatedAt, evidence,
				new TotpAuthenticationContext("browser:admin-client-" + action, InetAddress.getByName(request.getRemoteAddr()), correlation));
		IdentityClientManagement.Result result;
		try { result = operation.apply(context); }
		catch (RuntimeException ex) { session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true); throw ex; }
		return switch (result.status()) {
			case COMPLETED -> {
				Object body = result.secret() == null ? response(result.client()) : new IdentityClientSecretResponse(response(result.client()), result.secret());
				yield created ? ResponseEntity.created(URI.create(request.getContextPath() + "/api/admin/clients/" + result.client().id())).body(body) : ResponseEntity.ok(body);
			}
			case INVALID_SESSION -> invalidSession(actorId, correlation, request, response);
			case FORBIDDEN -> IdentityBrowserResponses.error(IdentityBrowserResponses.Error.FORBIDDEN);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case CONFLICT -> ResponseEntity.status(409).contentType(MediaType.TEXT_PLAIN).body("Client conflict");
			case NOT_FOUND -> ResponseEntity.notFound().build();
			case INVALID_INPUT, REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Client operation rejected");
		};
	}

	private ResponseEntity<?> invalidSession(UUID actorId, UUID correlationId, HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		this.administrators.recordAccessDenied(actorId, correlationId);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private static Runnable save(HttpServletResponse response) {
		return () -> { try { response.flushBuffer(); } catch (IOException ex) { throw new UncheckedIOException(ex); } };
	}

	@ExceptionHandler(NoSuchElementException.class)
	ResponseEntity<Void> missingClient() { return ResponseEntity.notFound().build(); }

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidClientRequest() { return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid client request"); }

	@ExceptionHandler(IdentityClientRequests.BodyTooLargeException.class)
	ResponseEntity<?> clientBodyTooLarge() { return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.PAYLOAD_TOO_LARGE); }

	private static IdentityClientConfiguration configuration(IdentityClientConfigurationRequest request) {
		return new IdentityClientConfiguration(request.displayName(), request.resourceId(), request.redirectUris(), Set.copyOf(request.scopes()), Set.copyOf(request.allowedRoleIds()));
	}

	private static IdentityClientResponse response(IdentityClient client) {
		var config = client.configuration();
		return new IdentityClientResponse(client.id(), new IdentityClientConfigurationResponse(config.displayName(), config.resourceId(), config.redirectUris(), config.scopes().stream().sorted().toList(), config.allowedRoleIds().stream().sorted().toList()),
				client.status(), client.version(), client.createdAt(), client.updatedAt(), client.secretRotatedAt());
	}

	private static String encodeCursor(IdentityClientPage.Cursor cursor) {
		if (cursor == null) { return null; }
		String value = "1\n" + cursor.createdAt() + "\n" + cursor.id() + "\n" + (cursor.status() == null ? "*" : cursor.status().name());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
	}

	private static IdentityClientPage.Cursor decodeCursor(String value) {
		if (value == null) { return null; }
		if (value.isEmpty() || value.length() > 512) { throw new IllegalArgumentException("Invalid client cursor"); }
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		String text = new String(bytes, StandardCharsets.UTF_8);
		String[] parts = text.split("\n", -1);
		if (parts.length != 4 || !parts[0].equals("1") || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) { throw new IllegalArgumentException("Invalid client cursor"); }
		try { return new IdentityClientPage.Cursor(Instant.parse(parts[1]), IdentityClientRequests.id(parts[2]), parts[3].equals("*") ? null : IdentityClient.Status.valueOf(parts[3])); }
		catch (DateTimeException ex) { throw new IllegalArgumentException("Invalid client cursor", ex); }
	}

}
