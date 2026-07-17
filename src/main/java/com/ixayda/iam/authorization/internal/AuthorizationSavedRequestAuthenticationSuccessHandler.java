package com.ixayda.iam.authorization.internal;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.util.UriComponentsBuilder;

final class AuthorizationSavedRequestAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private static final String INVALID_STATE = "Authorization login state is invalid";

	private final RequestCache requestCache;

	private final String issuer;

	private final String authorizationEndpoint;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	AuthorizationSavedRequestAuthenticationSuccessHandler(RequestCache requestCache,
			AuthorizationServerSettings settings) {
		this.requestCache = Objects.requireNonNull(requestCache, "Authorization request cache must not be null");
		Objects.requireNonNull(settings, "Authorization server settings must not be null");
		this.issuer = Objects.requireNonNull(settings.getIssuer(), "Authorization server issuer must not be null");
		this.authorizationEndpoint = Objects.requireNonNull(settings.getAuthorizationEndpoint(),
				"Authorization endpoint must not be null");
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (!isValid(savedRequest)) {
			throw failClosed(request, null);
		}
		String target;
		try {
			target = authorizationTarget(savedRequest);
		}
		catch (IllegalArgumentException exception) {
			throw failClosed(request, exception);
		}
		this.requestCache.removeRequest(request, response);
		clearAuthenticationFailure(request);
		this.redirectStrategy.sendRedirect(request, response, target);
	}

	private boolean isValid(SavedRequest savedRequest) {
		return savedRequest != null && "GET".equals(savedRequest.getMethod())
				&& AllowlistedAuthorizationRequestConverter.hasValidParameters(savedRequest.getParameterMap());
	}

	private String authorizationTarget(SavedRequest savedRequest) {
		UriComponentsBuilder target = UriComponentsBuilder.fromUriString(this.issuer)
			.path(this.authorizationEndpoint);
		for (Map.Entry<String, String[]> parameter : new TreeMap<>(savedRequest.getParameterMap()).entrySet()) {
			if (!AllowlistedAuthorizationRequestConverter.CONTINUE_PARAMETER.equals(parameter.getKey())) {
				target.queryParam(parameter.getKey(), (Object[]) parameter.getValue());
			}
		}
		return target.encode().toUriString();
	}

	private static void clearAuthenticationFailure(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		}
	}

	private static ServletException failClosed(HttpServletRequest request, IllegalArgumentException cause) {
		SecurityContextHolder.clearContext();
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		return cause == null ? new ServletException(INVALID_STATE) : new ServletException(INVALID_STATE, cause);
	}

}
