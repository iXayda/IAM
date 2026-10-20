package com.ixayda.iam.security;

import java.io.IOException;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.web.filter.OncePerRequestFilter;

/** Probes stay independent of browser admission budgets, audit writes and Cookie state. */
final class IdentityHealthRequestFilter extends OncePerRequestFilter {

	static final Set<String> PATHS = Set.of("/livez", "/readyz", "/actuator/health/liveness", "/actuator/health/readiness");
	private final HeaderWriter headers;

	IdentityHealthRequestFilter(HeaderWriter headers) { this.headers = headers; }

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		this.headers.writeHeaders(request, response);
		if (!request.isSecure()) { IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.BAD_REQUEST); return; }
		if (!"GET".equals(request.getMethod())) {
			response.setHeader("Allow", "GET"); IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.METHOD_NOT_ALLOWED); return;
		}
		if (request.getQueryString() != null || request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null
				|| request.getInputStream().read() != -1) {
			IdentityBrowserResponses.error(response, IdentityBrowserResponses.Error.BAD_REQUEST); return;
		}
		// MVC's default FlashMapManager calls getSession(false) even for a stateless Actuator handler.
		// Keep an unrelated stale Cookie from making liveness depend on the JDBC session store.
		chain.doFilter(new SessionlessRequest(request), response);
	}

	private static final class SessionlessRequest extends HttpServletRequestWrapper {
		SessionlessRequest(HttpServletRequest request) { super(request); }
		@Override public HttpSession getSession(boolean create) {
			if (create) { throw new IllegalStateException("Health probes cannot create a browser session"); }
			return null;
		}
		@Override public HttpSession getSession() { return getSession(true); }
		@Override public String getRequestedSessionId() { return null; }
		@Override public boolean isRequestedSessionIdValid() { return false; }
	}
}
