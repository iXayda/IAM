package com.ixayda.iam.authorization.internal;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

final class AuthorizationMfaAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final AuthenticationFailureHandler delegate = new SimpleUrlAuthenticationFailureHandler("/login?error");

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		clearChallenge(request);
		this.delegate.onAuthenticationFailure(request, response, exception);
	}

	static void clearChallenge(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(AuthorizationMfaLoginPageController.CHALLENGE_ATTRIBUTE);
		}
	}

}
