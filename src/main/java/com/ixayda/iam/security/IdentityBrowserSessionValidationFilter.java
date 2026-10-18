package com.ixayda.iam.security;

import java.io.IOException;
import java.util.UUID;

import com.ixayda.iam.service.IdentityBrowserSessions;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

final class IdentityBrowserSessionValidationFilter extends OncePerRequestFilter {

	private final IdentityBrowserSessions sessions;

	IdentityBrowserSessionValidationFilter(IdentityBrowserSessions sessions) {
		this.sessions = sessions;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		var authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.getPrincipal() instanceof UUID userId) {
			var session = request.getSession(false);
			if (session == null || !this.sessions.isAuthenticationCurrent(userId, session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT),
					session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION))) {
				SecurityContextHolder.clearContext();
				if (session != null) {
					session.invalidate();
				}
				IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.UNAUTHENTICATED);
				return;
			}
		}
		chain.doFilter(request, response);
	}

}
