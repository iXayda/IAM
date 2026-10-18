package com.ixayda.iam.controller;

import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityUserPageResponse;
import com.ixayda.iam.dto.IdentityUserResponse;
import com.ixayda.iam.dto.IdentityUserSearchRequest;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserPage;
import com.ixayda.iam.service.IdentityUsers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentityUserManagementController {

	private final IdentityUsers users;

	IdentityUserManagementController(IdentityUsers users) {
		this.users = users;
	}

	@InitBinder("userSearch")
	void searchBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
	}

	@Operation(operationId = "searchUsers", summary = "搜索用户", description = "需要当前管理员资格及有效的密码和 TOTP 管理会话。仅接受 keyword、status、pageSize、cursor 查询参数；默认每页 20 条，范围 1 至 100。游标须与原关键词和状态一起使用；按创建时间和 UUID 稳定排序，返回 nextCursor 为 null 时结束。拒绝重复参数、额外参数及请求体。")
	@ApiResponse(responseCode = "200", description = "用户分页结果")
	@ApiResponse(responseCode = "400", description = "查询条件、游标或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格或 MFA 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@GetMapping(path = "/api/admin/users", produces = MediaType.APPLICATION_JSON_VALUE)
	public IdentityUserPageResponse search(@org.springdoc.core.annotations.ParameterObject @ModelAttribute("userSearch") IdentityUserSearchRequest query, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of("keyword", "status", "pageSize", "cursor"), "Invalid user query");
		if ((request.getParameter("pageSize") != null && query.pageSize() == null)
				|| (request.getParameter("status") != null
						&& (query.status() == null || !query.status().name().equals(request.getParameter("status"))))) {
			throw new IllegalArgumentException("Invalid user query");
		}
		var page = this.users.search(query.keyword(), query.status(), query.pageSize() == null ? 20 : query.pageSize(), decodeCursor(query.cursor()));
		return new IdentityUserPageResponse(page.items().stream().map(IdentityUserManagementController::response).toList(), encodeCursor(page.nextCursor()));
	}

	@Operation(operationId = "getUser", summary = "查询指定用户", description = "需要有效的管理员 MFA 会话。userId 使用完整 UUID；不接受请求体及查询参数。仅返回身份资料，不返回凭据、恢复凭据、因素秘密或会话内容。")
	@ApiResponse(responseCode = "200", description = "用户身份资料")
	@ApiResponse(responseCode = "400", description = "用户标识或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "管理资格或 MFA 不满足要求", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "404", description = "用户不存在", content = @Content)
	@GetMapping(path = "/api/admin/users/{userId}", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<IdentityUserResponse> find(@PathVariable String userId, HttpServletRequest request) {
		IdentityQueryRequests.require(request, Set.of(), "Invalid user query");
		return this.users.findById(parseUserId(userId)).map(IdentityUserManagementController::response)
				.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
	}

	@ExceptionHandler({ IllegalArgumentException.class, BindException.class })
	ResponseEntity<String> invalidQuery() {
		return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("Invalid user query");
	}

	private static IdentityUserResponse response(IdentityUser user) {
		return new IdentityUserResponse(user.id(), user.username(), user.displayName(), user.status(), user.createdAt());
	}

	private static UUID parseUserId(String value) {
		UUID id = UUID.fromString(value);
		if (!id.toString().equalsIgnoreCase(value)) {
			throw new IllegalArgumentException("Invalid user id");
		}
		return id;
	}

	/** A cursor is a transport position, never authentication or permission to query users. */
	private static String encodeCursor(IdentityUserPage.Cursor cursor) {
		if (cursor == null) { return null; }
		String text = cursor.createdAt() + "\n" + cursor.id() + "\n" + (cursor.status() == null ? "" : cursor.status().name()) + "\n" + cursor.keyword();
		return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
	}

	private static IdentityUserPage.Cursor decodeCursor(String value) {
		if (value == null) { return null; }
		if (value.isEmpty() || value.length() > 1024) { throw new IllegalArgumentException("Invalid user cursor"); }
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		String text = new String(bytes, StandardCharsets.UTF_8);
		String[] parts = text.split("\n", -1);
		if (parts.length != 4 || !Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
			throw new IllegalArgumentException("Invalid user cursor");
		}
		try {
			Instant createdAt = Instant.parse(parts[0]);
			// PostgreSQL timestamps are finite and use microsecond resolution, as do issued cursors.
			if (createdAt.isBefore(Instant.parse("-4712-01-01T00:00:00Z")) || !createdAt.isBefore(Instant.parse("+294277-01-01T00:00:00Z"))
					|| createdAt.getNano() % 1000 != 0) {
				throw new IllegalArgumentException("Invalid user cursor");
			}
			return new IdentityUserPage.Cursor(createdAt, parseUserId(parts[1]), parts[3], parts[2].isEmpty() ? null : IdentityUser.Status.valueOf(parts[2]));
		}
		catch (DateTimeException ex) { throw new IllegalArgumentException("Invalid user cursor", ex); }
	}

}
