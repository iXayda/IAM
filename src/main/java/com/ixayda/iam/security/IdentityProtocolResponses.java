package com.ixayda.iam.security;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;

/** Protocol errors use the official OAuth response format and never reflect request values. */
final class IdentityProtocolResponses {

	static final String TOKEN_ENDPOINT = "/oauth2/token";
	static final String JWK_SET_ENDPOINT = "/oauth2/jwks";
	static final String USER_INFO_ENDPOINT = "/userinfo";
	static final String INTROSPECTION_ENDPOINT = "/oauth2/introspect";
	static final String AUTHORIZATION_ENDPOINT = "/oauth2/authorize";
	static final String INTERACTION_ENDPOINT = "/api/authorization-interactions";
	static final String OIDC_DISCOVERY_ENDPOINT = "/.well-known/openid-configuration";
	static final String OAUTH_DISCOVERY_ENDPOINT = "/.well-known/oauth-authorization-server";

	private IdentityProtocolResponses() { }

	static void error(HttpServletResponse response, int status, String code) throws IOException {
		error(response, status, code, "iam/token");
	}

	static void error(HttpServletResponse response, int status, String code, String basicRealm) throws IOException {
		response.setStatus(status);
		response.setHeader("Cache-Control", "no-store");
		response.setHeader("Pragma", "no-cache");
		if ("invalid_client".equals(code)) { response.setHeader("WWW-Authenticate", "Basic realm=\"" + basicRealm + "\""); }
		new OAuth2ErrorHttpMessageConverter().write(new OAuth2Error(code), null, new ServletServerHttpResponse(response));
	}

}
