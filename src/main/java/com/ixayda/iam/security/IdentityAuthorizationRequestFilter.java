package com.ixayda.iam.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.filter.OncePerRequestFilter;

/** Reject ambiguous transport before reading a browser session and bind only the configured protocol identity. */
final class IdentityAuthorizationRequestFilter extends OncePerRequestFilter {

	private final IdentityAuthorizationEndpoint endpoint;
	private final AuthorizationServerContext context;

	IdentityAuthorizationRequestFilter(IdentityAuthorizationEndpoint endpoint, AuthorizationServerSettings settings) {
		this.endpoint = endpoint;
		this.context = new AuthorizationServerContext() {
			@Override public String getIssuer() { return settings.getIssuer(); }
			@Override public AuthorizationServerSettings getAuthorizationServerSettings() { return settings; }
		};
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		try { validate(request, response); }
		catch (IdentityAuthorizationEndpoint.Failure failure) { this.endpoint.writeFailure(response, failure); return; }
		try {
			AuthorizationServerContextHolder.setContext(this.context);
			chain.doFilter(request, response);
		}
		catch (RuntimeException | ServletException | IOException failure) {
			// Session loading or response conversion can fail outside the trusted provider's own audit boundary.
			this.endpoint.rejected(request, 503, "server_error"); throw failure;
		}
		finally { AuthorizationServerContextHolder.resetContext(); }
	}

	private void validate(HttpServletRequest request, HttpServletResponse response) throws IOException {
		boolean authorization = request.getServletPath().equals(IdentityProtocolResponses.AUTHORIZATION_ENDPOINT);
		boolean completion = request.getServletPath().matches(IdentityProtocolResponses.INTERACTION_ENDPOINT + "/[^/]+/complete");
		String method = completion ? "POST" : "GET";
		if (!method.equals(request.getMethod())) {
			response.setHeader("Allow", method); throw this.endpoint.rejected(request, 405, "invalid_request");
		}
		if (request.getHeader("Authorization") != null || request.getHeader("DPoP") != null
				|| !authorization && request.getQueryString() != null) { throw this.endpoint.rejected(request, 400, "invalid_request"); }
		if (!completion) {
			if (request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null || request.getInputStream().read() != -1) {
				throw this.endpoint.rejected(request, 400, "invalid_request");
			}
		}
		else {
			try {
				var type = MediaType.parseMediaType(request.getContentType() == null ? "" : request.getContentType());
				if (!MediaType.APPLICATION_JSON.isCompatibleWith(type) || !"application".equals(type.getType()) || !"json".equals(type.getSubtype())
						|| type.getCharset() != null && !StandardCharsets.UTF_8.equals(type.getCharset())) { throw new IllegalArgumentException(); }
			}
			catch (IllegalArgumentException ex) { throw this.endpoint.rejected(request, 415, "invalid_request"); }
		}
		if (request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) { throw this.endpoint.rejected(request, 400, "invalid_request"); }
	}

}
