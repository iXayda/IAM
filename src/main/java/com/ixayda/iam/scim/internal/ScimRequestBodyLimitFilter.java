package com.ixayda.iam.scim.internal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import com.unboundid.scim2.common.messages.ErrorResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
final class ScimRequestBodyLimitFilter extends OncePerRequestFilter {

	private static final int MAX_BODY_BYTES = 128 * 1024;

	private static final String DETAIL = "The SCIM request body exceeds the supported size limit.";

	private final ScimJsonCodec codec;

	ScimRequestBodyLimitFilter(ScimJsonCodec codec) {
		this.codec = codec;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String method = request.getMethod();
		return !(method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))
				|| !request.getRequestURI().startsWith(request.getContextPath() + ScimMetadataController.BASE_PATH + "/");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			filterChain.doFilter(new BoundedRequest(request), response);
		}
		catch (ScimPayloadTooLargeException exception) {
			writeError(response);
		}
		catch (ServletException exception) {
			if (causedByPayloadLimit(exception)) {
				writeError(response);
				return;
			}
			throw exception;
		}
	}

	static boolean causedByPayloadLimit(Throwable exception) {
		for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
			if (cause instanceof ScimPayloadTooLargeException) {
				return true;
			}
		}
		return false;
	}

	static ErrorResponse errorResponse() {
		ErrorResponse error = new ErrorResponse(HttpStatus.PAYLOAD_TOO_LARGE.value());
		error.setScimType("tooMany");
		error.setDetail(DETAIL);
		return error;
	}

	private void writeError(HttpServletResponse response) throws IOException {
		if (response.isCommitted()) {
			return;
		}
		response.resetBuffer();
		response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
		response.setContentType(ScimMediaTypes.SCIM_JSON_VALUE);
		this.codec.write(response.getOutputStream(), errorResponse());
	}

	private static final class BoundedRequest extends HttpServletRequestWrapper {

		private BoundedServletInputStream inputStream;

		private BoundedRequest(HttpServletRequest request) {
			super(request);
		}

		@Override
		public ServletInputStream getInputStream() throws IOException {
			if (this.inputStream == null) {
				this.inputStream = new BoundedServletInputStream(super.getInputStream());
			}
			return this.inputStream;
		}

		@Override
		public BufferedReader getReader() throws IOException {
			String encoding = getCharacterEncoding();
			Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
			return new BufferedReader(new InputStreamReader(getInputStream(), charset));
		}

	}

	private static final class BoundedServletInputStream extends ServletInputStream {

		private final ServletInputStream delegate;

		private int bytesRead;

		private BoundedServletInputStream(ServletInputStream delegate) {
			this.delegate = delegate;
		}

		@Override
		public int read() throws IOException {
			int value = this.delegate.read();
			if (value >= 0) {
				record(1);
			}
			return value;
		}

		@Override
		public int read(byte[] buffer, int offset, int length) throws IOException {
			int remainingWithSentinel = MAX_BODY_BYTES - this.bytesRead + 1;
			int count = this.delegate.read(buffer, offset, Math.min(length, Math.max(remainingWithSentinel, 1)));
			if (count > 0) {
				record(count);
			}
			return count;
		}

		@Override
		public boolean isFinished() {
			return this.delegate.isFinished();
		}

		@Override
		public boolean isReady() {
			return this.delegate.isReady();
		}

		@Override
		public void setReadListener(ReadListener readListener) {
			this.delegate.setReadListener(readListener);
		}

		private void record(int count) throws ScimPayloadTooLargeException {
			this.bytesRead += count;
			if (this.bytesRead > MAX_BODY_BYTES) {
				throw new ScimPayloadTooLargeException();
			}
		}

	}

}
