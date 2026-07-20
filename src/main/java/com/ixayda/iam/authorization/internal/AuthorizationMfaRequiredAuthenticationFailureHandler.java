package com.ixayda.iam.authorization.internal;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

final class AuthorizationMfaRequiredAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final AuthenticationFailureHandler delegate = new SimpleUrlAuthenticationFailureHandler("/login?error");

	private final RedirectStrategy redirects = new DefaultRedirectStrategy();

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		HttpSession session = request.getSession(false);
		if (exception instanceof AuthorizationMfaRequiredException required && session != null) {
			session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			session.setAttribute(AuthorizationMfaLoginPageController.CHALLENGE_ATTRIBUTE, required.challenge());
			this.redirects.sendRedirect(request, response, AuthorizationMfaLoginPageController.PATH);
			return;
		}
		if (session != null) {
			session.removeAttribute(AuthorizationMfaLoginPageController.CHALLENGE_ATTRIBUTE);
		}
		this.delegate.onAuthenticationFailure(request, response, exception);
	}

}
