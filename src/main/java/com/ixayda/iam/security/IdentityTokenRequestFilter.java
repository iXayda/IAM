package com.ixayda.iam.security;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.SecurityAudits;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

/** Bounds the confidential back-channel before native client authentication or any grant mutation. */
final class IdentityTokenRequestFilter extends OncePerRequestFilter {

	private static final String GRANT_SUBMITTED = IdentityTokenRequestFilter.class.getName() + ".grantSubmitted";
	private static final Set<String> BODY_AUTHENTICATION = Set.of("client_id", "client_secret", "client_assertion", "client_assertion_type");
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityTokenRequestFilter(SecurityAudits audits, PlatformTransactionManager manager) {
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		// Native server configuration installs CSRF during initialization. This secret-authenticated chain
		// uses its public skip contract before the filter can load or change an unrelated browser session.
		CsrfFilter.skipRequest(request);
		if (!"POST".equals(request.getMethod())) {
			response.setHeader("Allow", "POST"); reject(request, response, 405, "invalid_request"); return;
		}
		if (!isForm(request.getContentType())) { reject(request, response, 415, "invalid_request"); return; }
		if (request.getQueryString() != null || request.getHeader("DPoP") != null
				|| request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)
				|| request.getParameterMap().keySet().stream().anyMatch(BODY_AUTHENTICATION::contains)
				|| Collections.list(request.getHeaders("Authorization")).size() > 1) {
			reject(request, response, 400, "invalid_request"); return;
		}
		// The native client filter's WebAuthenticationDetails calls getSession(false) even with
		// SessionCreationPolicy.STATELESS. Keep that read from refreshing a supplied IAM Cookie.
		chain.doFilter(new StatelessRequest(request), response);
	}

	Object grantEvidence(HttpServletRequest request) {
		// Only the two registered native converters can reach this point. Their providers own failure audits.
		request.setAttribute(GRANT_SUBMITTED, true);
		var correlation = IdentityBrowserDiagnostics.correlationId(request);
		return "authorization_code".equals(request.getParameter("grant_type"))
				? new IdentityAuthorizationCodeProvider.RequestEvidence(correlation) : new IdentityRefreshTokenProvider.RequestEvidence(correlation);
	}

	AuthenticationFailureHandler failureHandler() {
		return (request, response, failure) -> {
			String code = failure instanceof OAuth2AuthenticationException oauth ? oauth.getError().getErrorCode() : "server_error";
			if (!Set.of("invalid_client", "invalid_request", "invalid_grant", "invalid_scope", "unsupported_grant_type").contains(code)) { code = "server_error"; }
			reject(request, response, "invalid_client".equals(code) ? 401 : "server_error".equals(code) ? 503 : 400, code);
		};
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, int status, String code) throws IOException {
		if (!Boolean.TRUE.equals(request.getAttribute(GRANT_SUBMITTED))) {
			var authentication = SecurityContextHolder.getContext().getAuthentication();
			String actor = authentication instanceof OAuth2ClientAuthenticationToken client && client.isAuthenticated()
					? "client:" + client.getRegisteredClient().getId() : "anonymous";
			try {
				this.transaction.executeWithoutResult(ignored -> this.audits.recordFailure(Action.TOKEN_REQUEST_REJECTED, null,
						new SecurityAuditContext(actor, "protocol:token", IdentityBrowserDiagnostics.correlationId(request))));
			}
			catch (RuntimeException ex) { status = 503; code = "server_error"; }
		}
		SecurityContextHolder.clearContext();
		IdentityProtocolResponses.error(response, status, code);
	}

	private static boolean isForm(String contentType) {
		try {
			var type = contentType == null ? null : MediaType.parseMediaType(contentType);
			return type != null && "application".equals(type.getType()) && "x-www-form-urlencoded".equals(type.getSubtype())
					&& (type.getCharset() == null || java.nio.charset.StandardCharsets.UTF_8.equals(type.getCharset()));
		}
		catch (IllegalArgumentException ex) { return false; }
	}

	private static final class StatelessRequest extends HttpServletRequestWrapper {
		StatelessRequest(HttpServletRequest request) { super(request); }
		@Override public HttpSession getSession(boolean create) {
			if (create) { throw new IllegalStateException("Protocol back-channel cannot create a browser session"); }
			return null;
		}
		@Override public HttpSession getSession() { return getSession(true); }
		@Override public String getRequestedSessionId() { return null; }
		@Override public boolean isRequestedSessionIdValid() { return false; }
		@Override public boolean isRequestedSessionIdFromCookie() { return false; }
		@Override public boolean isRequestedSessionIdFromURL() { return false; }
		@Override public String changeSessionId() { throw new IllegalStateException("Protocol back-channel cannot rotate a browser session"); }
	}

}
