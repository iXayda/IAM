package com.ixayda.iam.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

import com.ixayda.iam.service.IdentityBrowserSessions;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.web.filter.OncePerRequestFilter;

/** Bounds public work and defers response publication until Spring Session has committed. */
final class IdentityBrowserBoundaryFilter extends OncePerRequestFilter {

	private final IdentityBrowserSessions sessions;
	private final int requestsPerSecond;
	private final Semaphore permits;
	private final LongSupplier nanoTime;
	private final HeaderWriter securityHeaders;
	private final IdentityIntrospectionFailures introspectionFailures;
	private long window;
	private int requests;
	private boolean throttleAudited;
	private boolean throttleAuditInProgress;

	IdentityBrowserBoundaryFilter(IdentityBrowserSessions sessions, int requestsPerSecond, int concurrency, HeaderWriter securityHeaders) {
		this(sessions, requestsPerSecond, concurrency, securityHeaders, System::nanoTime, null);
	}

	IdentityBrowserBoundaryFilter(IdentityBrowserSessions sessions, int requestsPerSecond, int concurrency, HeaderWriter securityHeaders, IdentityIntrospectionFailures failures) {
		this(sessions, requestsPerSecond, concurrency, securityHeaders, System::nanoTime, failures);
	}

	IdentityBrowserBoundaryFilter(IdentityBrowserSessions sessions, int requestsPerSecond, int concurrency, HeaderWriter securityHeaders, LongSupplier nanoTime) {
		this(sessions, requestsPerSecond, concurrency, securityHeaders, nanoTime, null);
	}

	private IdentityBrowserBoundaryFilter(IdentityBrowserSessions sessions, int requestsPerSecond, int concurrency, HeaderWriter securityHeaders, LongSupplier nanoTime, IdentityIntrospectionFailures failures) {
		if (requestsPerSecond < 1 || requestsPerSecond > 10_000 || concurrency < 1 || concurrency > 128) {
			throw new IllegalArgumentException("Browser admission limits are invalid");
		}
		this.sessions = sessions;
		this.requestsPerSecond = requestsPerSecond;
		this.permits = new Semaphore(concurrency);
		this.nanoTime = nanoTime;
		this.securityHeaders = securityHeaders;
		this.introspectionFailures = failures;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		boolean admitted = false;
		var stage = IdentityBrowserDiagnostics.Stage.ADMISSION;
		try {
			this.securityHeaders.writeHeaders(request, response);
			admitted = admit();
			if (!admitted) {
				if (!auditThrottle()) {
					reject(request, response, IdentityBrowserResponses.Error.SERVICE_UNAVAILABLE, false);
					return;
				}
				response.setHeader("Retry-After", "1");
				reject(request, response, IdentityBrowserResponses.Error.TOO_MANY_REQUESTS, false);
				return;
			}
			if (!request.isSecure()) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (request.getContentLengthLong() > 8192) {
				reject(request, response, IdentityBrowserResponses.Error.PAYLOAD_TOO_LARGE);
				return;
			}
			boolean clientChange = request.getMethod().equals("POST") && (request.getServletPath().equals("/api/admin/clients")
					|| request.getServletPath().matches("/api/admin/clients/[^/]+/(configuration|disable|enable|secret/rotate)"));
			boolean resourceCredentialChange = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/resources/[^/]+/validation-credential/(rotate|disable)");
			if (request.getMethod().equals("POST") && (request.getServletPath().equals("/login") || clientChange || resourceCredentialChange)
					&& (request.getContentType() == null || !request.getContentType().split(";", 2)[0].equalsIgnoreCase("application/json"))) {
				reject(request, response, IdentityBrowserResponses.Error.UNSUPPORTED_MEDIA_TYPE);
				return;
			}
			boolean passwordChange = request.getServletPath().equals("/api/me/password");
			boolean profileChange = request.getServletPath().equals("/api/me/profile");
			boolean administratorMfa = request.getServletPath().equals("/admin/mfa");
			boolean userRoleChange = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/users/[^/]+/roles/[^/]+/(grant|revoke)");
			boolean roleCreation = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/resources/[^/]+/roles");
			boolean roleName = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/resource-roles/[^/]+/name");
			boolean roleState = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/resource-roles/[^/]+/(disable|enable)");
			boolean resourceCreation = request.getMethod().equals("POST") && request.getServletPath().equals("/api/admin/resources");
			boolean resourceName = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/resources/[^/]+/name");
			boolean resourceState = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/resources/[^/]+/(disable|enable)");
			boolean userCreation = request.getMethod().equals("POST") && request.getServletPath().equals("/api/admin/users");
			boolean userProfileUpdate = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/users/[^/]+/profile");
			boolean userStateChange = request.getMethod().equals("POST")
					&& request.getServletPath().matches("/api/admin/users/[^/]+/(disable|enable)");
			boolean userSessionRevocation = request.getMethod().equals("POST") && request.getServletPath().matches("/api/admin/users/[^/]+/sessions/revoke-all");
			boolean setupManagement = request.getMethod().equals("POST")
					&& request.getServletPath().matches("/api/admin/users/[^/]+/setup(/cancel)?");
			boolean setupCompletion = request.getMethod().equals("POST") && request.getServletPath().equals("/api/account-setup/complete");
			boolean recoveryManagement = request.getMethod().equals("POST")
					&& request.getServletPath().matches("/api/admin/users/[^/]+/password-recovery(/cancel)?");
			boolean recoveryCompletion = request.getMethod().equals("POST") && request.getServletPath().equals("/api/password-recovery/complete");
			boolean recoveryCodeIssuance = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/recovery-codes");
			boolean totpEnrollment = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/enrollment");
			boolean totpConfirmation = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/enrollment/confirm");
			boolean totpCancellation = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/enrollment/cancel");
			boolean totpReplacement = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/replacement");
			boolean totpReplacementCompletion = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/replacement/complete");
			boolean totpRecovery = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/recovery");
			boolean totpRecoveryCompletion = request.getMethod().equals("POST") && request.getServletPath().equals("/api/me/mfa/totp/recovery/complete");
			boolean accountChange = userProfileUpdate || userSessionRevocation || userRoleChange || roleCreation || roleName || roleState || resourceCreation || resourceName || resourceState || totpRecovery || totpRecoveryCompletion || totpReplacement || totpReplacementCompletion || totpEnrollment || totpConfirmation || totpCancellation || recoveryCodeIssuance || passwordChange || profileChange || administratorMfa || userCreation || userStateChange || setupManagement || setupCompletion || recoveryManagement || recoveryCompletion;
			if (request.getMethod().equals("POST") && accountChange
					&& (request.getContentType() == null || !request.getContentType().split(";", 2)[0].equalsIgnoreCase("application/x-www-form-urlencoded"))) {
				reject(request, response, IdentityBrowserResponses.Error.UNSUPPORTED_MEDIA_TYPE);
				return;
			}
			if ((accountChange || clientChange || resourceCredentialChange) && request.getQueryString() != null) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			// Let the servlet container enforce its form limit, including chunked requests, before opening a session.
			try {
				request.getParameterMap();
			}
			catch (IllegalStateException ex) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (accountChange && request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (userProfileUpdate && !Set.of("displayName", "code", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (profileChange && !Set.of("displayName", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if ((totpEnrollment && !Set.of("currentPassword", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (totpConfirmation && !Set.of("factorId", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (totpCancellation && !Set.of("factorId", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (totpReplacement && !Set.of("currentPassword", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (totpReplacementCompletion && !Set.of("replacementId", "token", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (totpRecovery && !Set.of("currentPassword", "recoveryCode", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (totpRecoveryCompletion && !Set.of("recoveryId", "token", "code", "_csrf").containsAll(request.getParameterMap().keySet()))) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if ((administratorMfa || userStateChange || userSessionRevocation || setupManagement || recoveryManagement || recoveryCodeIssuance) && !Set.of("code", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if ((userRoleChange && !Set.of("version", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (roleCreation && !Set.of("roleCode", "displayName", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (roleName && !Set.of("version", "displayName", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (roleState && !Set.of("version", "code", "_csrf").containsAll(request.getParameterMap().keySet()))) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if ((resourceCreation && !Set.of("audience", "displayName", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (resourceName && !Set.of("version", "displayName", "code", "_csrf").containsAll(request.getParameterMap().keySet()))
					|| (resourceState && !Set.of("version", "code", "_csrf").containsAll(request.getParameterMap().keySet()))) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (userCreation && !Set.of("username", "displayName", "code", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (setupCompletion && !Set.of("userId", "token", "password", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (recoveryCompletion && !Set.of("userId", "token", "newPassword", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(request, response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			int responseLimit = request.getMethod().equals("GET")
					&& Set.of("/v3/api-docs", "/v3/api-docs.yaml").contains(request.getServletPath())
					? 2_097_152 : 131_072;
			var deferred = new DeferredResponse(response, responseLimit);
			stage = IdentityBrowserDiagnostics.Stage.REQUEST_PROCESSING;
			chain.doFilter(request, deferred);
			headers(response);
			stage = IdentityBrowserDiagnostics.Stage.RESPONSE_PUBLICATION;
			deferred.publish();
		}
		catch (RuntimeException | ServletException | IOException ex) {
			if (response.isCommitted()) {
				throw ex;
			}
			IdentityBrowserDiagnostics.recordFailure(request, stage, ex);
			response.reset();
			this.securityHeaders.writeHeaders(request, response);
			reject(request, response, IdentityBrowserResponses.Error.SERVICE_UNAVAILABLE, admitted);
		}
		finally {
			if (admitted) {
				this.permits.release();
			}
		}
	}

	private synchronized boolean admit() {
		long now = this.nanoTime.getAsLong() / 1_000_000_000L;
		if (this.window != now) {
			this.window = now;
			this.requests = 0;
			this.throttleAudited = false;
		}
		if (this.requests >= this.requestsPerSecond) {
			return false;
		}
		this.requests++;
		return this.permits.tryAcquire();
	}

	private boolean auditThrottle() {
		long auditWindow;
		synchronized (this) {
			if (this.throttleAudited) {
				return true;
			}
			if (this.throttleAuditInProgress) {
				return false;
			}
			this.throttleAuditInProgress = true;
			auditWindow = this.window;
		}
		boolean recorded = false;
		try {
			this.sessions.recordEntryThrottle();
			recorded = true;
			return true;
		}
		finally {
			synchronized (this) {
				this.throttleAuditInProgress = false;
				if (recorded && this.window == auditWindow) {
					this.throttleAudited = true;
				}
			}
		}
	}

	private static void headers(HttpServletResponse response) {
		response.setHeader("Cache-Control", "no-store");
		response.setHeader("Pragma", "no-cache");
		response.setHeader("X-Content-Type-Options", "nosniff");
		response.setHeader("Referrer-Policy", "no-referrer");
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, IdentityBrowserResponses.Error error) throws IOException {
		reject(request, response, error, true);
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, IdentityBrowserResponses.Error error, boolean auditIntrospection) throws IOException {
		headers(response);
		// Rejected admission already has a bounded aggregate throttle audit; do not create per-request database work outside its permit.
		if (auditIntrospection && this.introspectionFailures != null && request.getServletPath().equals(IdentityProtocolResponses.INTROSPECTION_ENDPOINT)) {
			try { this.introspectionFailures.record(request); }
			catch (RuntimeException ex) { error = IdentityBrowserResponses.Error.SERVICE_UNAVAILABLE; }
		}
		if (Set.of(IdentityProtocolResponses.TOKEN_ENDPOINT, IdentityProtocolResponses.JWK_SET_ENDPOINT, IdentityProtocolResponses.USER_INFO_ENDPOINT, IdentityProtocolResponses.AUTHORIZATION_ENDPOINT,
				IdentityProtocolResponses.INTROSPECTION_ENDPOINT, IdentityProtocolResponses.OIDC_DISCOVERY_ENDPOINT, IdentityProtocolResponses.OAUTH_DISCOVERY_ENDPOINT).contains(request.getServletPath())
				|| request.getServletPath().startsWith(IdentityProtocolResponses.INTERACTION_ENDPOINT + "/")) {
			int status = switch (error) {
				case PAYLOAD_TOO_LARGE -> 413;
				case UNSUPPORTED_MEDIA_TYPE -> 415;
				case TOO_MANY_REQUESTS -> 429;
				case SERVICE_UNAVAILABLE -> 503;
				default -> 400;
			};
			IdentityProtocolResponses.error(response, status, status == 503 ? "server_error" : status == 429 ? "temporarily_unavailable" : "invalid_request");
		}
		else { IdentityBrowserResponses.error(response, error); }
	}

	private static final class DeferredResponse extends HttpServletResponseWrapper {

		private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		private final int limit;
		private boolean overflowed;
		private final ServletOutputStream output = new ServletOutputStream() {
			@Override
			public void write(int value) throws IOException {
				if (buffer.size() >= limit) {
					overflowed = true;
					throw new IOException("Browser response exceeds its bound");
				}
				buffer.write(value);
			}
			@Override
			public void write(byte[] values, int offset, int length) throws IOException {
				Objects.checkFromIndexSize(offset, length, values.length);
				if (length > limit - buffer.size()) {
					overflowed = true;
					throw new IOException("Browser response exceeds its bound");
				}
				buffer.write(values, offset, length);
			}
			@Override
			public boolean isReady() { return true; }
			@Override
			public void setWriteListener(WriteListener listener) { throw new IllegalStateException("Asynchronous responses are unsupported"); }
		};
		private PrintWriter writer;

		DeferredResponse(HttpServletResponse response, int limit) {
			super(response);
			this.limit = limit;
		}

		@Override
		public ServletOutputStream getOutputStream() { return this.output; }

		@Override
		public PrintWriter getWriter() {
			if (this.writer == null) {
				setCharacterEncoding(StandardCharsets.UTF_8.name());
				this.writer = new PrintWriter(new OutputStreamWriter(this.output, StandardCharsets.UTF_8)) {
					// Native protocol writers close after serialization. Publication still belongs to
					// the outer boundary, after every session or grant transaction has committed.
					@Override public void close() { flush(); }
				};
			}
			return this.writer;
		}

		@Override
		public void flushBuffer() { if (this.writer != null) { this.writer.flush(); } }

		@Override
		public void resetBuffer() {
			flushBuffer();
			this.buffer.reset();
		}

		@Override
		public void reset() {
			resetBuffer();
			super.reset();
			this.writer = null;
		}

		@Override
		public void sendRedirect(String location) {
			sendRedirect(location, 302, true);
		}

		@Override
		public void sendRedirect(String location, boolean clearBuffer) { sendRedirect(location, 302, clearBuffer); }

		@Override
		public void sendRedirect(String location, int status) { sendRedirect(location, status, true); }

		@Override
		public void sendRedirect(String location, int status, boolean clearBuffer) {
			if (clearBuffer) { resetBuffer(); }
			setStatus(status);
			setHeader("Location", location);
		}

		@Override
		public void sendError(int status) { resetBuffer(); setStatus(status); }

		@Override
		public void sendError(int status, String message) { sendError(status); }

		void publish() throws IOException {
			flushBuffer();
			if (this.overflowed || (this.writer != null && this.writer.checkError())) {
				throw new IOException("Browser response could not be buffered");
			}
			var response = (HttpServletResponse) getResponse();
			response.setContentLength(this.buffer.size());
			this.buffer.writeTo(response.getOutputStream());
		}

	}

}
