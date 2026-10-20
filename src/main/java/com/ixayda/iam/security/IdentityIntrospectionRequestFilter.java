package com.ixayda.iam.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenIntrospectionAuthenticationConverter;
import org.springframework.web.filter.OncePerRequestFilter;

/** Native form conversion and serialization under a stateless, single-resource credential boundary. */
final class IdentityIntrospectionRequestFilter extends OncePerRequestFilter {

	private final OAuth2TokenIntrospectionEndpointFilter endpoint;
	private final IdentityIntrospectionFailures failures;

	IdentityIntrospectionRequestFilter(IdentityIntrospectionProvider provider, IdentityIntrospectionFailures failures) {
		this.failures = failures;
		this.endpoint = new OAuth2TokenIntrospectionEndpointFilter(new ProviderManager(List.of(provider)), IdentityProtocolResponses.INTROSPECTION_ENDPOINT);
		var basic = new ClientSecretBasicAuthenticationConverter(); var requests = new OAuth2TokenIntrospectionAuthenticationConverter();
		this.endpoint.setAuthenticationConverter(request -> {
			org.springframework.security.core.Authentication proof;
			try { proof = basic.convert(request); }
			catch (OAuth2AuthenticationException ex) { throw new OAuth2AuthenticationException("invalid_client"); }
			if (!(proof instanceof OAuth2ClientAuthenticationToken client) || !(client.getCredentials() instanceof String secret)) { throw new OAuth2AuthenticationException("invalid_client"); }
			var resource = provider.authenticateResource(client.getPrincipal().toString(), secret);
			var context = SecurityContextHolder.createEmptyContext(); context.setAuthentication(resource); SecurityContextHolder.setContext(context);
			var converted = requests.convert(request);
			if (!(converted instanceof OAuth2TokenIntrospectionAuthenticationToken introspection)) { throw new OAuth2AuthenticationException("invalid_request"); }
			introspection.setDetails(new IdentityIntrospectionProvider.Evidence(IdentityBrowserDiagnostics.correlationId(request)));
			return introspection;
		});
		var responses = new OAuth2TokenIntrospectionHttpMessageConverter();
		this.endpoint.setAuthenticationSuccessHandler((request, response, authentication) -> {
			var result = (OAuth2TokenIntrospectionAuthenticationToken) authentication;
			if (!result.getTokenClaims().isActive()) { this.failures.markRecorded(request); }
			responses.write(result.getTokenClaims(), null, new ServletServerHttpResponse(response));
		});
		this.endpoint.setAuthenticationFailureHandler((request, response, failure) -> {
			String code = failure instanceof OAuth2AuthenticationException oauth ? oauth.getError().getErrorCode() : "server_error";
			if (!Set.of("invalid_request", "invalid_client").contains(code)) { code = "server_error"; }
			reject(request, response, code.equals("invalid_client") ? 401 : code.equals("server_error") ? 503 : 400, code);
		});
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		try {
			if (!"POST".equals(request.getMethod())) { response.setHeader("Allow", "POST"); reject(request, response, 405, "invalid_request"); return; }
			if (!isForm(request.getContentType())) { reject(request, response, 415, "invalid_request"); return; }
			if (request.getQueryString() != null || request.getHeader("DPoP") != null || Collections.list(request.getHeaders("Authorization")).size() > 1
					|| !Set.of("token", "token_type_hint").containsAll(request.getParameterMap().keySet())
					|| request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)
					|| request.getParameter("token") != null && request.getParameter("token").length() > 16_384
					|| request.getParameter("token_type_hint") != null && !request.getParameter("token_type_hint").matches("[\\x20-\\x7e]{0,128}")) {
				reject(request, response, 400, "invalid_request"); return;
			}
			if (request.getHeader("Authorization") != null && request.getHeader("Authorization").length() > 512) { reject(request, response, 401, "invalid_client"); return; }
			this.endpoint.doFilter(request, response, (ignoredRequest, ignoredResponse) -> { throw new IllegalStateException("Introspection did not handle its exact path"); });
		}
		finally { SecurityContextHolder.clearContext(); }
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, int status, String code) throws IOException {
		try { this.failures.record(request); }
		catch (RuntimeException ex) { status = 503; code = "server_error"; }
		IdentityProtocolResponses.error(response, status, code, "iam/introspection");
	}

	private static boolean isForm(String contentType) {
		try {
			var type = contentType == null ? null : MediaType.parseMediaType(contentType);
			return type != null && "application".equals(type.getType()) && "x-www-form-urlencoded".equals(type.getSubtype())
					&& (type.getCharset() == null || StandardCharsets.UTF_8.equals(type.getCharset()));
		}
		catch (IllegalArgumentException ex) { return false; }
	}

}
