package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityProtocolClients;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

/** Shared token-request proof and issuer checks; current registration is rechecked under the workflow locks. */
final class IdentityTokenRequests {

	private IdentityTokenRequests() { }

	static IdentityProtocolClients.Snapshot client(Object principal) {
		if (!(principal instanceof OAuth2ClientAuthenticationToken client) || !client.isAuthenticated() || client.getCredentials() != null
				|| !ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(client.getClientAuthenticationMethod())
				|| !(client.getDetails() instanceof IdentityProtocolClients.Snapshot snapshot) || !snapshot.registration().equals(client.getRegisteredClient())) {
			throw failure("invalid_client");
		}
		return snapshot;
	}

	static String issuer(OAuth2Authorization authorization) {
		var context = AuthorizationServerContextHolder.getContext();
		if (context == null || context.getAuthorizationServerSettings().getIssuer() == null
				|| !context.getIssuer().equals(context.getAuthorizationServerSettings().getIssuer())) { throw failure("server_error"); }
		String issuer;
		try { issuer = requireIssuer(context.getIssuer()); }
		catch (IllegalArgumentException ex) { throw failure("server_error"); }
		OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		String expected = (issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer) + context.getAuthorizationServerSettings().getAuthorizationEndpoint();
		if (request == null || !expected.equals(request.getAuthorizationUri())) { throw failure("invalid_grant"); }
		return issuer;
	}

	static String requireIssuer(String value) {
		try {
			var uri = requireHttpsUri(value);
			if (!uri.getRawPath().isEmpty() && !"/".equals(uri.getRawPath())) { throw new IllegalArgumentException(); }
			return value;
		}
		catch (IllegalArgumentException ex) { throw new IllegalArgumentException("An explicit HTTPS issuer at the root path is required"); }
	}

	static java.net.URI requireHttpsUri(String value) {
		try {
			var uri = java.net.URI.create(value);
			if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
					|| uri.getPort() == 0 || uri.getPort() > 65535 || uri.getPort() < -1 || uri.getRawAuthority().endsWith(":")) {
				throw new IllegalArgumentException();
			}
			return uri;
		}
		catch (IllegalArgumentException | NullPointerException ex) { throw new IllegalArgumentException("An explicit HTTPS URI is required"); }
	}

	static OAuth2AuthenticationException failure(String code) {
		String description = switch (code) {
			case "invalid_client" -> "Client authentication failed";
			case "invalid_grant" -> "Authorization grant is invalid";
			case "invalid_request" -> "Token request is invalid";
			case "invalid_scope" -> "Requested scope is invalid";
			default -> { code = "server_error"; yield "Token exchange is unavailable"; }
		};
		return new OAuth2AuthenticationException(new OAuth2Error(code, description, null));
	}

}
