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

	private IdentityProtocolResponses() { }

	static void error(HttpServletResponse response, int status, String code) throws IOException {
		response.setStatus(status);
		response.setHeader("Cache-Control", "no-store");
		response.setHeader("Pragma", "no-cache");
		if ("invalid_client".equals(code)) { response.setHeader("WWW-Authenticate", "Basic realm=\"iam/token\""); }
		new OAuth2ErrorHttpMessageConverter().write(new OAuth2Error(code), null, new ServletServerHttpResponse(response));
	}

}
