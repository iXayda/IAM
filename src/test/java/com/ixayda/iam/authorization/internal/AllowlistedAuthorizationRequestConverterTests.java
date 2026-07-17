package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

class AllowlistedAuthorizationRequestConverterTests {

	private static final Authentication AUTHENTICATION =
			UsernamePasswordAuthenticationToken.unauthenticated("client", "");

	@Test
	void acceptsTheSupportedAuthorizationCodeAndOpenIdParameters() {
		MockHttpServletRequest request = authorizationRequest();
		request.addParameter("response_type", "code");
		request.addParameter("client_id", "web-client");
		request.addParameter("redirect_uri", "https://client.example.test/callback");
		request.addParameter("scope", "openid profile");
		request.addParameter("state", "state-value");
		request.addParameter("code_challenge", "A".repeat(43));
		request.addParameter("code_challenge_method", "S256");
		request.addParameter("nonce", "nonce-value");
		request.addParameter("prompt", "login");

		assertThat(converter().convert(request)).isSameAs(AUTHENTICATION);
	}

	@Test
	void rejectsUnknownRepeatedAndEmptyParameters() {
		MockHttpServletRequest unknown = authorizationRequest();
		unknown.addParameter("resource", "https://api.example.test");
		assertInvalidRequest(unknown);

		MockHttpServletRequest repeated = authorizationRequest();
		repeated.addParameter("nonce", "first", "second");
		assertInvalidRequest(repeated);

		MockHttpServletRequest empty = authorizationRequest();
		empty.addParameter("prompt", " ");
		assertInvalidRequest(empty);

		MockHttpServletRequest forgedContinuation = authorizationRequest();
		forgedContinuation.addParameter("continue", "unexpected");
		assertInvalidRequest(forgedContinuation);
	}

	@Test
	void ignoresRequestsNotHandledByTheAuthorizationCodeConverter() {
		AllowlistedAuthorizationRequestConverter converter =
				new AllowlistedAuthorizationRequestConverter((request) -> null);
		MockHttpServletRequest request = authorizationRequest();
		request.addParameter("unrelated", "value");

		assertThat(converter.convert(request)).isNull();
	}

	@Test
	void removesTheSavedRequestContinuationMarkerBeforeProtocolConversion() {
		MockHttpServletRequest request = authorizationRequest();
		request.addParameter("response_type", "code");
		request.addParameter("continue", "");
		AllowlistedAuthorizationRequestConverter converter = new AllowlistedAuthorizationRequestConverter((filtered) -> {
			assertThat(filtered.getParameter("continue")).isNull();
			assertThat(filtered.getParameter("response_type")).isEqualTo("code");
			return AUTHENTICATION;
		});

		assertThat(converter.convert(request)).isSameAs(AUTHENTICATION);
	}

	private static AllowlistedAuthorizationRequestConverter converter() {
		return new AllowlistedAuthorizationRequestConverter((request) -> AUTHENTICATION);
	}

	private static MockHttpServletRequest authorizationRequest() {
		return new MockHttpServletRequest("GET", "/oauth2/authorize");
	}

	private static void assertInvalidRequest(MockHttpServletRequest request) {
		assertThatThrownBy(() -> converter().convert(request))
			.isInstanceOfSatisfying(OAuth2AuthorizationCodeRequestAuthenticationException.class,
					(exception) -> assertThat(exception.getError().getErrorCode())
						.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));
	}

}
