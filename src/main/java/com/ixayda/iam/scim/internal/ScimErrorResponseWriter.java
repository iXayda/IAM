package com.ixayda.iam.scim.internal;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.unboundid.scim2.common.messages.ErrorResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

final class ScimErrorResponseWriter implements AuthenticationEntryPoint, AccessDeniedHandler {

	private static final String FORBIDDEN_DETAIL = "Access to this SCIM resource is forbidden.";

	private static final String UNAUTHORIZED_DETAIL = "A valid bearer token is required for this SCIM resource.";

	private static final String INVALID_REQUEST_DETAIL = "The bearer token request is invalid.";

	private final ScimJsonCodec codec;

	ScimErrorResponseWriter(ScimJsonCodec codec) {
		this.codec = codec;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {
		if (authenticationException instanceof OAuth2AuthenticationException oauth2Exception
				&& oauth2Exception.getError() instanceof BearerTokenError bearerError) {
			HttpStatus status = bearerError.getHttpStatus();
			String detail = status == HttpStatus.BAD_REQUEST ? INVALID_REQUEST_DETAIL : UNAUTHORIZED_DETAIL;
			write(response, status, detail, "Bearer error=\"" + bearerError.getErrorCode() + "\"");
			return;
		}
		write(response, HttpStatus.UNAUTHORIZED, UNAUTHORIZED_DETAIL, "Bearer");
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			org.springframework.security.access.AccessDeniedException accessDeniedException) throws IOException {
		String requiredScope = requiredScope(request);
		String challenge = requiredScope == null ? "Bearer"
				: "Bearer error=\"insufficient_scope\", scope=\"" + requiredScope + "\"";
		write(response, HttpStatus.FORBIDDEN, FORBIDDEN_DETAIL, challenge);
	}

	private static String requiredScope(HttpServletRequest request) {
		String path = request.getRequestURI().substring(request.getContextPath().length());
		boolean collection = path.equals(ScimMetadataController.BASE_PATH + "/Users")
				|| path.equals(ScimMetadataController.BASE_PATH + "/Groups");
		boolean resource = isDirectResource(path, ScimMetadataController.BASE_PATH + "/Users/")
				|| isDirectResource(path, ScimMetadataController.BASE_PATH + "/Groups/");
		return switch (request.getMethod()) {
			case "GET", "HEAD" -> collection || resource ? "scim.read" : null;
			case "POST" -> collection ? "scim.write" : null;
			case "PUT", "PATCH", "DELETE" -> resource ? "scim.write" : null;
			default -> null;
		};
	}

	private static boolean isDirectResource(String path, String prefix) {
		return path.startsWith(prefix) && path.length() > prefix.length()
				&& path.indexOf('/', prefix.length()) < 0;
	}

	private void write(HttpServletResponse response, HttpStatus status, String detail, String challenge)
			throws IOException {
		if (response.isCommitted()) {
			return;
		}
		ErrorResponse error = new ErrorResponse(status.value());
		error.setDetail(detail);
		response.setStatus(status.value());
		response.setContentType(ScimMediaTypes.SCIM_JSON_VALUE);
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge);
		this.codec.write(response.getOutputStream(), error);
	}

}
