package com.ixayda.iam.security;

import java.io.IOException;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/** Public native JWK publication terminates before browser context or session processing. */
final class IdentityJwkRequestFilter extends OncePerRequestFilter {

	private final NimbusJwkSetEndpointFilter endpoint;

	IdentityJwkRequestFilter(JWKSource<SecurityContext> source) {
		this.endpoint = new NimbusJwkSetEndpointFilter((selector, context) -> {
			var keys = source.get(selector, context);
			if (keys.isEmpty()) { throw new KeySourceException("Public signing keys are unavailable"); }
			return keys;
		}, IdentityProtocolResponses.JWK_SET_ENDPOINT);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		if (!"GET".equals(request.getMethod())) {
			response.setHeader("Allow", "GET"); IdentityProtocolResponses.error(response, 405, "invalid_request"); return;
		}
		if (request.getQueryString() != null || request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null
				|| !request.getParameterMap().isEmpty() || request.getInputStream().read() != -1) {
			IdentityProtocolResponses.error(response, 400, "invalid_request"); return;
		}
		this.endpoint.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
			throw new IllegalStateException("Public JWK endpoint did not handle its exact path");
		});
	}

}
