package com.ixayda.iam.security;

import java.io.IOException;
import java.util.UUID;

import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

final class IdentityBrowserSessionValidationFilter extends OncePerRequestFilter {

	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;

	IdentityBrowserSessionValidationFilter(IdentityBrowserSessions sessions, IdentityAdministratorSessions administrators) {
		this.sessions = sessions;
		this.administrators = administrators;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		var authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.getPrincipal() instanceof UUID userId) {
			var session = request.getSession(false);
			if (!authentication.isAuthenticated() || session == null || !this.sessions.isAuthenticationCurrent(userId, session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT),
					session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION))) {
				SecurityContextHolder.clearContext();
				if (session != null) {
					session.invalidate();
				}
				String path = request.getServletPath();
				if (path.startsWith("/admin/") || path.startsWith("/api/admin/")) {
					this.administrators.recordAccessDenied(userId, IdentityBrowserDiagnostics.correlationId(request));
				}
				IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.UNAUTHENTICATED);
				return;
			}
			var current = SecurityContextHolder.createEmptyContext();
			current.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(userId, null,
					this.administrators.authorities(userId, session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT),
							session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION))));
			SecurityContextHolder.setContext(current);
		}
		chain.doFilter(request, response);
	}

}
