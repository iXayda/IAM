package com.ixayda.iam.security;

import java.nio.charset.StandardCharsets;
import java.util.List;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.*;

class IdentityProtocolTransportTests {

	@ParameterizedTest
	@ValueSource(strings = { "/oauth2/jwks" })
	void unknownLengthBodiesWithoutTransferEncodingCannotBypassHeaderOnlyProtocols(String path) throws Exception {
		var request = new MockHttpServletRequest("GET", path) {
			@Override public long getContentLengthLong() { return -1; }
			@Override public int getContentLength() { return -1; }
		};
		request.setServletPath(path); request.setContent("private-unknown-length-body".getBytes(StandardCharsets.UTF_8));
		var response = new MockHttpServletResponse();
		var filter = new IdentityJwkRequestFilter((selector, context) -> { throw new AssertionError("The body must be rejected before key lookup"); });
		filter.doFilter(request, response, (req, res) -> fail("No fallback endpoint is allowed"));
		assertThat(response.getStatus()).isEqualTo(400); assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"invalid_request\"}");
		assertThat(response.getHeaders("Set-Cookie")).isEmpty(); assertThat(request.getSession(false)).isNull();
	}

	@Test
	void knownLengthPublicKeyBodiesAreRejectedBeforeKeyLookup() throws Exception {
		var request = new MockHttpServletRequest("GET", "/oauth2/jwks");
		request.setServletPath("/oauth2/jwks"); request.setContent("private-known-length-body".getBytes(StandardCharsets.UTF_8));
		var response = new MockHttpServletResponse();
		var filter = new IdentityJwkRequestFilter((selector, context) -> { throw new AssertionError("The body must be rejected before key lookup"); });
		filter.doFilter(request, response, (req, res) -> fail("No fallback endpoint is allowed"));
		assertThat(response.getStatus()).isEqualTo(400); assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"invalid_request\"}");
		assertThat(response.getHeaders("Set-Cookie")).isEmpty(); assertThat(request.getSession(false)).isNull();
	}

	@ParameterizedTest
	@ValueSource(longs = { -1, 0 })
	void publicKeyReadsWithoutABodyPublishKeysWithoutCreatingASession(long declaredLength) throws Exception {
		var request = new MockHttpServletRequest("GET", "/oauth2/jwks") {
			@Override public long getContentLengthLong() { return declaredLength; }
			@Override public int getContentLength() { return (int) declaredLength; }
		};
		request.setServletPath("/oauth2/jwks");
		var response = new MockHttpServletResponse();
		var key = new RSAKeyGenerator(2048).keyID("test-signing-key").generate().toPublicJWK();
		var filter = new IdentityJwkRequestFilter((selector, context) -> List.of(key));
		filter.doFilter(request, response, (req, res) -> fail("The public key endpoint must handle its exact path"));
		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(JWKSet.parse(response.getContentAsString()).getKeys()).containsExactly(key);
		assertThat(response.getContentType()).startsWith("application/json");
		assertThat(response.getHeaders("Set-Cookie")).isEmpty(); assertThat(request.getSession(false)).isNull();
	}

}
