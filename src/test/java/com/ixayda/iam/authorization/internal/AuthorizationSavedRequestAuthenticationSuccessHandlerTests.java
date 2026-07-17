package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.savedrequest.RequestCache;

class AuthorizationSavedRequestAuthenticationSuccessHandlerTests {

	@AfterEach
	void clearSecurityContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void invalidatesTheAuthenticatedSessionWhenTheSavedRequestIsMissing() {
		RequestCache requestCache = mock(RequestCache.class);
		AuthorizationServerSettings settings = AuthorizationServerSettings.builder()
			.issuer("https://issuer.example.test")
			.build();
		AuthorizationSavedRequestAuthenticationSuccessHandler handler =
				new AuthorizationSavedRequestAuthenticationSuccessHandler(requestCache, settings);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(mock(Authentication.class));
		SecurityContextHolder.setContext(context);

		assertThatThrownBy(() -> handler.onAuthenticationSuccess(request, new MockHttpServletResponse(),
				mock(Authentication.class)))
			.isInstanceOf(jakarta.servlet.ServletException.class)
			.hasMessage("Authorization login state is invalid");
		assertThat(session.isInvalid()).isTrue();
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

}
