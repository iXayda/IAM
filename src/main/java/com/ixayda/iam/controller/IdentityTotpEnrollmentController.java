package com.ixayda.iam.controller;

import java.beans.PropertyEditorSupport;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import com.ixayda.iam.dto.IdentityMfaRecoveryCodesResponse;
import com.ixayda.iam.dto.IdentityTotpEnrollmentCancellationRequest;
import com.ixayda.iam.dto.IdentityTotpEnrollmentConfirmationRequest;
import com.ixayda.iam.dto.IdentityTotpEnrollmentRequest;
import com.ixayda.iam.dto.IdentityTotpEnrollmentResponse;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityBrowserResponses;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityTotpEnrollments;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ExtendedServletRequestDataBinder;

@RestController
@RegisterReflectionForBinding({ IdentityMfaRecoveryCodesResponse.class, IdentityTotpEnrollmentResponse.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentityTotpEnrollmentController {

	private final IdentityTotpEnrollments enrollments;
	private final SecurityContextLogoutHandler logout = new SecurityContextLogoutHandler();

	IdentityTotpEnrollmentController(IdentityTotpEnrollments enrollments) { this.enrollments = enrollments; }

	@InitBinder({ "totpEnrollment", "totpConfirmation", "totpCancellation" })
	void enrollmentBinding(ExtendedServletRequestDataBinder binder) {
		binder.setDeclarativeBinding(true);
		binder.setHeaderPredicate(header -> false);
		binder.registerCustomEditor(UUID.class, new PropertyEditorSupport() {
			@Override public void setAsText(String text) {
				UUID id = UUID.fromString(text);
				if (!id.toString().equalsIgnoreCase(text)) { throw new IllegalArgumentException("Full UUID is required"); }
				setValue(id);
			}
		});
	}

	@Operation(operationId = "beginCurrentTotpEnrollment", summary = "开始本人 TOTP 注册", description = "需要有效密码会话、当前密码及 CSRF。每次开始都重新校验本人当前密码，与所有密码验证入口共享来源和账号失败预算；会话本身不足以注册因素。仅用于尚无活动因素的本人；重新开始会替换旧待确认因素，旧密钥和因素标识失效。十分钟内必须使用同一会话确认。密码校验、因素创建、审计及会话保存原子提交，不延长密码认证绝对期限。密钥及 otpauth URI 仅本次交付，由独立身份前端配置认证器；不提供重新读取秘密的接口。禁止记录、缓存或放入浏览器持久存储。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。提交后网络交付失败可重新开始。不会授予管理权限。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "待确认因素和注册秘密，仅本次交付", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityTotpEnrollmentResponse.class)))
	@ApiResponse(responseCode = "400", description = "当前密码被拒绝、已有活动因素或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "密码共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpEnrollmentRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/enrollment", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> begin(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpEnrollment") IdentityTotpEnrollmentRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var context = new PasswordAuthenticationContext("browser:totp-enrollment", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		return withPasswordSession(request, response, (session, persist) -> {
			var result = this.enrollments.begin(userId, session.id(), session.version(), session.authenticatedAt(), command.currentPassword(), context, persist);
			if (result.status() != IdentityTotpEnrollments.Status.COMPLETED) { return failure(result.status(), request, response); }
			var enrollment = result.enrollment();
			return ResponseEntity.ok(new IdentityTotpEnrollmentResponse(enrollment.factorId(), enrollment.secret(), enrollment.provisioningUri(), enrollment.expiresAt()));
		});
	}

	@Operation(operationId = "confirmCurrentTotpEnrollment", summary = "确认本人 TOTP 注册", description = "需要开始注册时的同一密码会话及 CSRF，提交 factorId 和新认证器六位 code。与所有 TOTP 验证入口共享失败预算。因素激活、验证码消费、首组恢复码、必需审计和会话保存原子提交；不会授予管理权限或延长密码认证绝对期限。成功仅本次交付十个恢复码，独立身份前端应提醒离线保存并清理内存。事务失败保留原待确认状态；提交后网络交付失败时因素已经激活，应使用新验证码调用恢复码重新生成接口。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "200", description = "因素已激活，首组恢复码仅本次交付", content = @Content(mediaType = "application/json", schema = @Schema(implementation = IdentityMfaRecoveryCodesResponse.class)))
	@ApiResponse(responseCode = "400", description = "注册绑定、因素或验证码被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "429", description = "TOTP 共享失败预算耗尽，或入口限流；仅入口限流提供 Retry-After", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpEnrollmentConfirmationRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/enrollment/confirm", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> confirm(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpConfirmation") IdentityTotpEnrollmentConfirmationRequest command,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		var context = new TotpAuthenticationContext("browser:totp-enrollment", InetAddress.getByName(request.getRemoteAddr()), UUID.randomUUID());
		return withPasswordSession(request, response, (session, persist) -> {
			var result = this.enrollments.confirm(userId, session.id(), session.version(), session.authenticatedAt(),
					session.factorId(), command.factorId(), command.code(), context, persist);
			if (result.status() != IdentityTotpEnrollments.Status.COMPLETED) { return failure(result.status(), request, response); }
			var issued = result.codeSet();
			return ResponseEntity.ok(new IdentityMfaRecoveryCodesResponse(issued.generationId(), issued.codes(), issued.issuedAt()));
		});
	}

	@Operation(operationId = "cancelCurrentTotpEnrollment", summary = "取消本人待确认 TOTP 注册", description = "需要开始注册时的同一密码会话及 CSRF，提交 factorId。只能删除绑定的待确认因素，不能删除活动因素，也不能取消其他会话的新注册。允许取消已过期的待确认注册；不需要解密密钥。拒绝查询参数、重复及额外字段，不从请求头绑定业务字段。")
	@Parameter(name = "X-CSRF-TOKEN", in = ParameterIn.HEADER, description = "同一会话的 /api/csrf 令牌；也支持 _csrf 表单字段", schema = @Schema(type = "string"))
	@ApiResponse(responseCode = "204", description = "待确认注册已取消，无响应体", content = @Content)
	@ApiResponse(responseCode = "400", description = "注册绑定或因素被拒绝，或请求格式无效", content = { @Content(mediaType = "text/plain", schema = @Schema(type = "string")), @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")) })
	@ApiResponse(responseCode = "403", description = "CSRF 缺失或无效", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@ApiResponse(responseCode = "415", description = "需要 application/x-www-form-urlencoded", content = @Content(mediaType = "application/json", schema = @Schema(ref = "#/components/schemas/IdentityErrorResponse")))
	@io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/x-www-form-urlencoded", schema = @Schema(implementation = IdentityTotpEnrollmentCancellationRequest.class)))
	@PostMapping(path = "/api/me/mfa/totp/enrollment/cancel", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> cancel(@Parameter(hidden = true) @AuthenticationPrincipal UUID userId,
			@Parameter(hidden = true) @ModelAttribute("totpCancellation") IdentityTotpEnrollmentCancellationRequest command,
			HttpServletRequest request, HttpServletResponse response) {
		var audit = new SecurityAuditContext("user:" + userId, "browser:totp-enrollment", UUID.randomUUID());
		return withPasswordSession(request, response, (session, persist) -> {
			var status = this.enrollments.cancel(userId, session.id(), session.version(), session.authenticatedAt(),
					session.factorId(), command.factorId(), audit, persist);
			return status == IdentityTotpEnrollments.Status.COMPLETED ? ResponseEntity.noContent().build() : failure(status, request, response);
		});
	}

	private ResponseEntity<?> withPasswordSession(HttpServletRequest request, HttpServletResponse response,
			BiFunction<PasswordSession, Consumer<UUID>, ResponseEntity<?>> operation) {
		var session = request.getSession(false);
		if (session == null || !(session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version)
				|| !(session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long authenticatedAt)) {
			return invalidSession(request, response);
		}
		UUID boundFactor = session.getAttribute(IdentityBrowserSessions.TOTP_ENROLLMENT) instanceof UUID id ? id : null;
		try {
			return operation.apply(new PasswordSession(session.getId(), version, authenticatedAt, boundFactor), factorId -> {
				if (factorId == null) { session.removeAttribute(IdentityBrowserSessions.TOTP_ENROLLMENT); }
				else { session.setAttribute(IdentityBrowserSessions.TOTP_ENROLLMENT, factorId); }
				try { response.flushBuffer(); }
				catch (IOException ex) { throw new UncheckedIOException(ex); }
			});
		}
		catch (RuntimeException ex) {
			// Never let the finalizer retry a mutable session after its surrounding workflow rolls back.
			session.setAttribute(IdentityBrowserSessions.PERSISTENCE_FAILED, true);
			throw ex;
		}
	}

	private ResponseEntity<?> failure(IdentityTotpEnrollments.Status status, HttpServletRequest request, HttpServletResponse response) {
		return switch (status) {
			case INVALID_SESSION -> invalidSession(request, response);
			case THROTTLED -> ResponseEntity.status(429).contentType(MediaType.TEXT_PLAIN).body("Verification temporarily unavailable");
			case REJECTED -> ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body("TOTP enrollment rejected");
			case COMPLETED -> throw new IllegalStateException("Unexpected completed enrollment");
		};
	}

	private ResponseEntity<?> invalidSession(HttpServletRequest request, HttpServletResponse response) {
		SecurityContextHolder.clearContext();
		this.logout.logout(request, response, null);
		return IdentityBrowserResponses.error(IdentityBrowserResponses.Error.UNAUTHENTICATED);
	}

	private record PasswordSession(String id, long version, long authenticatedAt, UUID factorId) { }

}
