package com.ixayda.iam.security;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/** Official discovery responses with an explicit allowlist of the HTTP capabilities actually enabled. */
final class IdentityDiscoveryRequestFilter extends OncePerRequestFilter {

	private final AuthorizationServerContext context;
	private final OidcProviderConfigurationEndpointFilter oidc = new OidcProviderConfigurationEndpointFilter();
	private final OAuth2AuthorizationServerMetadataEndpointFilter oauth = new OAuth2AuthorizationServerMetadataEndpointFilter();

	IdentityDiscoveryRequestFilter(AuthorizationServerSettings settings) {
		String issuer = IdentityTokenRequests.requireIssuer(settings.getIssuer());
		this.context = new AuthorizationServerContext() {
			@Override public String getIssuer() { return issuer; }
			@Override public AuthorizationServerSettings getAuthorizationServerSettings() { return settings; }
		};
		this.oidc.setProviderConfigurationCustomizer(builder -> builder.claims(claims -> describe(claims, settings, true)));
		this.oauth.setAuthorizationServerMetadataCustomizer(builder -> builder.claims(claims -> describe(claims, settings, false)));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		if (!"GET".equals(request.getMethod())) {
			response.setHeader("Allow", "GET"); IdentityProtocolResponses.error(response, 405, "invalid_request"); return;
		}
		if (request.getQueryString() != null || request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null
				|| request.getInputStream().read() != -1) {
			IdentityProtocolResponses.error(response, 400, "invalid_request"); return;
		}
		try {
			AuthorizationServerContextHolder.setContext(this.context);
			if (request.getServletPath().equals(IdentityProtocolResponses.OIDC_DISCOVERY_ENDPOINT)) { this.oidc.doFilter(request, response, chain); }
			else { this.oauth.doFilter(request, response, chain); }
		}
		finally { AuthorizationServerContextHolder.resetContext(); }
	}

	private static void describe(Map<String, Object> claims, AuthorizationServerSettings settings, boolean oidc) {
		claims.clear(); claims.putAll(metadata(settings, oidc));
	}

	private static Map<String, Object> metadata(AuthorizationServerSettings settings, boolean oidc) {
		String issuer = settings.getIssuer(); String base = issuer.replaceFirst("/$", "");
		var claims = new LinkedHashMap<String, Object>();
		claims.put("issuer", issuer);
		claims.put("authorization_endpoint", base + settings.getAuthorizationEndpoint());
		claims.put("token_endpoint", base + settings.getTokenEndpoint());
		claims.put("jwks_uri", base + settings.getJwkSetEndpoint());
		claims.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic"));
		claims.put("response_types_supported", List.of("code"));
		claims.put("response_modes_supported", List.of("query"));
		claims.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
		claims.put("code_challenge_methods_supported", List.of("S256"));
		claims.put("scopes_supported", List.of("openid", "profile", "offline_access"));
		if (oidc) {
			claims.put("userinfo_endpoint", base + settings.getOidcUserInfoEndpoint());
			claims.put("subject_types_supported", List.of("public"));
			claims.put("id_token_signing_alg_values_supported", List.of("RS256"));
			claims.put("claims_supported", List.of("iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "name", "preferred_username"));
			claims.put("claims_parameter_supported", false);
			claims.put("request_parameter_supported", false);
			claims.put("request_uri_parameter_supported", false);
		}
		return claims;
	}

}
