package com.ixayda.iam.scim.internal;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.unboundid.scim2.common.messages.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

final class ScimErrorResponseWriter implements AuthenticationEntryPoint, AccessDeniedHandler {

	private static final String FORBIDDEN_DETAIL = "Access to this SCIM resource is forbidden.";

	private final ScimJsonCodec codec;

	ScimErrorResponseWriter(ScimJsonCodec codec) {
		this.codec = codec;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {
		writeForbidden(response);
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			org.springframework.security.access.AccessDeniedException accessDeniedException) throws IOException {
		writeForbidden(response);
	}

	private void writeForbidden(HttpServletResponse response) throws IOException {
		if (response.isCommitted()) {
			return;
		}
		ErrorResponse error = new ErrorResponse(HttpStatus.FORBIDDEN.value());
		error.setDetail(FORBIDDEN_DETAIL);
		response.setStatus(HttpStatus.FORBIDDEN.value());
		response.setContentType(ScimMediaTypes.SCIM_JSON_VALUE);
		this.codec.write(response.getOutputStream(), error);
	}

}
