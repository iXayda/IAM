package com.ixayda.iam.security;

import java.nio.charset.StandardCharsets;
import java.util.List;

import com.ixayda.iam.service.SecurityAudits;
import com.ixayda.iam.service.IdentityAuthorizationInteractions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityProtocolTransportTests {

	@ParameterizedTest
	@ValueSource(strings = { "/oauth2/jwks", "/userinfo", "/oauth2/authorize", "/api/authorization-interactions/opaque-handle" })
	void unknownLengthBodiesWithoutTransferEncodingCannotBypassHeaderOnlyProtocols(String path) throws Exception {
		var request = new MockHttpServletRequest("GET", path) {
			@Override public long getContentLengthLong() { return -1; }
			@Override public int getContentLength() { return -1; }
		};
		request.setServletPath(path); request.setContent("private-unknown-length-body".getBytes(StandardCharsets.UTF_8));
		var response = new MockHttpServletResponse();
		if (path.equals("/oauth2/authorize") || path.startsWith("/api/authorization-interactions/")) {
			var settings = AuthorizationServerSettings.builder().issuer("https://iam.example").build();
			var provider = mock(IdentityAuthorizationRequestProvider.class);
			var endpoint = new IdentityAuthorizationEndpoint(settings, "https://iam.example/identity/authorize", provider, mock(IdentityProtocolClients.class),
					mock(IdentityBrowserSessions.class), mock(IdentityAuthorizationInteractions.class), mock(SecurityAudits.class), mock(PlatformTransactionManager.class));
			new IdentityAuthorizationRequestFilter(endpoint, settings).doFilter(request, response, (req, res) -> fail("No browser or authorization access is allowed"));
			verifyNoInteractions(provider);
		}
		else if (path.equals("/userinfo")) {
			var provider = mock(IdentityUserInfoProvider.class);
			var filter = new IdentityUserInfoRequestFilter(provider, mock(SecurityAudits.class), mock(PlatformTransactionManager.class));
			filter.doFilter(request, response, (req, res) -> fail("The body must be rejected before grant use"));
			verifyNoInteractions(provider);
			assertThat(response.getHeader("WWW-Authenticate")).contains("Bearer ", "error=\"invalid_request\"");
		}
		else {
			var filter = new IdentityJwkRequestFilter((selector, context) -> { throw new AssertionError("The body must be rejected before key lookup"); });
			filter.doFilter(request, response, (req, res) -> fail("No fallback endpoint is allowed"));
		}
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
