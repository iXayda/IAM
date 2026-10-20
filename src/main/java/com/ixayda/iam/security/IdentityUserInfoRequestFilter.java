package com.ixayda.iam.security;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.SecurityAudits;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

/** Header-only Bearer transport, mandatory denial audit and native UserInfo serialization; no browser context is loaded. */
final class IdentityUserInfoRequestFilter extends OncePerRequestFilter {

	private final OidcUserInfoEndpointFilter endpoint;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityUserInfoRequestFilter(IdentityUserInfoProvider provider, SecurityAudits audits, PlatformTransactionManager manager) {
		this.audits = audits; this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
		this.endpoint = new OidcUserInfoEndpointFilter(new ProviderManager(List.of(provider)), IdentityProtocolResponses.USER_INFO_ENDPOINT);
		var resolver = new DefaultBearerTokenResolver();
		resolver.setAllowFormEncodedBodyParameter(false); resolver.setAllowUriQueryParameter(false);
		this.endpoint.setAuthenticationConverter(request -> {
			String bearer = resolver.resolve(request);
			if (bearer == null) { throw new AuthenticationRequiredException(); }
			return new OidcUserInfoAuthenticationToken(new BearerTokenAuthenticationToken(bearer));
		});
		this.endpoint.setAuthenticationFailureHandler((request, response, failure) -> {
			String code = failure instanceof OAuth2AuthenticationException oauth ? oauth.getError().getErrorCode() : "server_error";
			if (!Set.of("invalid_request", "invalid_token", "insufficient_scope").contains(code)) { code = "server_error"; }
			UUID subject = failure instanceof IdentityUserInfoProvider.DeniedException denied ? denied.subject() : null;
			reject(request, response, switch (code) { case "invalid_token" -> 401; case "insufficient_scope" -> 403; case "server_error" -> 503; default -> 400; },
					code, subject, failure instanceof AuthenticationRequiredException);
		});
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		if (!Set.of("GET", "POST").contains(request.getMethod())) {
			response.setHeader("Allow", "GET, POST"); reject(request, response, 405, "invalid_request", null, false); return;
		}
		if (request.getQueryString() != null || request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null
				|| request.getHeader("DPoP") != null || Collections.list(request.getHeaders("Authorization")).size() > 1
				|| !request.getParameterMap().isEmpty() || request.getInputStream().read() != -1) {
			reject(request, response, 400, "invalid_request", null, false); return;
		}
		this.endpoint.doFilter(request, response, (ignoredRequest, ignoredResponse) -> {
			throw new IllegalStateException("UserInfo endpoint did not handle its exact path");
		});
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, int status, String code, UUID subject, boolean challengeOnly) throws IOException {
		try {
			this.transaction.executeWithoutResult(ignored -> this.audits.recordFailure(Action.USER_INFO_REJECTED, subject,
					new SecurityAuditContext(subject == null ? "anonymous" : "user:" + subject, "protocol:userinfo", IdentityBrowserDiagnostics.correlationId(request))));
		}
		catch (RuntimeException ex) { status = 503; code = "server_error"; challengeOnly = false; }
		if (status == 400 || status == 401 || status == 403) {
			response.setHeader("WWW-Authenticate", "Bearer realm=\"iam/userinfo\"" + (challengeOnly ? "" : ", error=\"" + code + "\""
					+ (status == 403 ? ", scope=\"openid\"" : "")));
		}
		if (challengeOnly) {
			response.setStatus(401); response.setHeader("Cache-Control", "no-store"); response.setHeader("Pragma", "no-cache");
		}
		else { IdentityProtocolResponses.error(response, status, code); }
	}

	private static final class AuthenticationRequiredException extends OAuth2AuthenticationException {
		AuthenticationRequiredException() { super("invalid_token"); }
	}

}
