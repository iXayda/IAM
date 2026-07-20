package com.ixayda.iam.authorization.internal;

import java.io.IOException;
import java.util.Objects;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

final class AuthorizationMfaAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final AuthenticationSuccessHandler delegate;

	AuthorizationMfaAuthenticationSuccessHandler(AuthenticationSuccessHandler delegate) {
		this.delegate = Objects.requireNonNull(delegate, "Authentication success handler must not be null");
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		AuthorizationMfaAuthenticationFailureHandler.clearChallenge(request);
		this.delegate.onAuthenticationSuccess(request, response, authentication);
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		onAuthenticationSuccess(request, response, authentication);
	}

}
