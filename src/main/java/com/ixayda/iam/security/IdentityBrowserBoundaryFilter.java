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
	private long window;
	private int requests;
	private boolean throttleAudited;
	private boolean throttleAuditInProgress;

	IdentityBrowserBoundaryFilter(IdentityBrowserSessions sessions, int requestsPerSecond, int concurrency, HeaderWriter securityHeaders) {
		this(sessions, requestsPerSecond, concurrency, securityHeaders, System::nanoTime);
	}

	IdentityBrowserBoundaryFilter(IdentityBrowserSessions sessions, int requestsPerSecond, int concurrency, HeaderWriter securityHeaders, LongSupplier nanoTime) {
		if (requestsPerSecond < 1 || requestsPerSecond > 10_000 || concurrency < 1 || concurrency > 128) {
			throw new IllegalArgumentException("Browser admission limits are invalid");
		}
		this.sessions = sessions;
		this.requestsPerSecond = requestsPerSecond;
		this.permits = new Semaphore(concurrency);
		this.nanoTime = nanoTime;
		this.securityHeaders = securityHeaders;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		boolean admitted = false;
		var stage = IdentityBrowserDiagnostics.Stage.ADMISSION;
		try {
			this.securityHeaders.writeHeaders(request, response);
			if (!request.isSecure()) {
				reject(response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			admitted = admit();
			if (!admitted) {
				if (!auditThrottle()) {
					reject(response, IdentityBrowserResponses.Error.SERVICE_UNAVAILABLE);
					return;
				}
				response.setHeader("Retry-After", "1");
				reject(response, IdentityBrowserResponses.Error.TOO_MANY_REQUESTS);
				return;
			}
			if (request.getContentLengthLong() > 8192) {
				reject(response, IdentityBrowserResponses.Error.PAYLOAD_TOO_LARGE);
				return;
			}
			if (request.getMethod().equals("POST") && request.getServletPath().equals("/login")
					&& (request.getContentType() == null || !request.getContentType().split(";", 2)[0].equalsIgnoreCase("application/json"))) {
				reject(response, IdentityBrowserResponses.Error.UNSUPPORTED_MEDIA_TYPE);
				return;
			}
			boolean passwordChange = request.getServletPath().equals("/api/me/password");
			boolean profileChange = request.getServletPath().equals("/api/me/profile");
			boolean accountChange = passwordChange || profileChange;
			if (request.getMethod().equals("POST") && accountChange
					&& (request.getContentType() == null || !request.getContentType().split(";", 2)[0].equalsIgnoreCase("application/x-www-form-urlencoded"))) {
				reject(response, IdentityBrowserResponses.Error.UNSUPPORTED_MEDIA_TYPE);
				return;
			}
			if (accountChange && request.getQueryString() != null) {
				reject(response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			// Let the servlet container enforce its form limit, including chunked requests, before opening a session.
			try {
				request.getParameterMap();
			}
			catch (IllegalStateException ex) {
				reject(response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (accountChange && request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) {
				reject(response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			if (profileChange && !Set.of("displayName", "_csrf").containsAll(request.getParameterMap().keySet())) {
				reject(response, IdentityBrowserResponses.Error.BAD_REQUEST);
				return;
			}
			var deferred = new DeferredResponse(response, 131_072);
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
			reject(response, IdentityBrowserResponses.Error.SERVICE_UNAVAILABLE);
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

	private static void reject(HttpServletResponse response, IdentityBrowserResponses.Error error) throws IOException {
		headers(response);
		IdentityBrowserResponses.error(response, error);
	}

	private static final class DeferredResponse extends HttpServletResponseWrapper {

		private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		private final int limit;
		private final ServletOutputStream output = new ServletOutputStream() {
			@Override
			public void write(int value) throws IOException {
				if (buffer.size() >= limit) {
					throw new IOException("Browser response exceeds its bound");
				}
				buffer.write(value);
			}
			@Override
			public void write(byte[] values, int offset, int length) throws IOException {
				Objects.checkFromIndexSize(offset, length, values.length);
				if (length > limit - buffer.size()) {
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
				this.writer = new PrintWriter(new OutputStreamWriter(this.output, StandardCharsets.UTF_8));
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
			if (this.writer != null && this.writer.checkError()) {
				throw new IOException("Browser response could not be buffered");
			}
			var response = (HttpServletResponse) getResponse();
			response.setContentLength(this.buffer.size());
			this.buffer.writeTo(response.getOutputStream());
		}

	}

}
