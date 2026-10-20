package com.ixayda.iam.security;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.IdentityAuthorizationInteractions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.SecurityAudits;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/** Native authorization navigation and the independent frontend's browser-bound interaction adapter. */
public final class IdentityAuthorizationEndpoint {

	private static final String OWNER = "iam.authorizationInteractionOwner";
	private static final String ORIGINAL = IdentityAuthorizationEndpoint.class.getName() + ".original";
	private final IdentityAuthorizationRequestProvider provider;
	private final IdentityProtocolClients clients;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthorizationInteractions interactions;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;
	private final String frontend;
	private final String authorizationUri;
	private final OAuth2AuthorizationEndpointFilter filter;

	IdentityAuthorizationEndpoint(AuthorizationServerSettings settings, String frontend, IdentityAuthorizationRequestProvider provider,
			IdentityProtocolClients clients, IdentityBrowserSessions sessions, IdentityAuthorizationInteractions interactions,
			SecurityAudits audits, PlatformTransactionManager transactions) {
		this.provider = provider; this.clients = clients; this.sessions = sessions; this.interactions = interactions; this.audits = audits;
		this.frontend = requireFrontend(settings.getIssuer(), frontend);
		this.authorizationUri = settings.getIssuer().replaceFirst("/$", "") + settings.getAuthorizationEndpoint();
		this.transaction = new TransactionTemplate(transactions);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
		this.filter = new OAuth2AuthorizationEndpointFilter(new ProviderManager(List.of(provider)), settings.getAuthorizationEndpoint());
		this.filter.setAuthenticationConverter(this::convert);
		this.filter.setAuthenticationDetailsSource(this::evidence);
		this.filter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());
		this.filter.setAuthenticationFailureHandler(this::authorizationFailure);
	}

	Filter filter() { return this.filter; }

	private Authentication convert(HttpServletRequest request) {
		var browser = currentBrowser(request);
		var converted = (OAuth2AuthorizationCodeRequestAuthenticationToken) new OAuth2AuthorizationCodeRequestAuthenticationConverter().convert(request);
		if (converted == null) { throw new OAuth2AuthenticationException("invalid_request"); }
		var original = new OAuth2AuthorizationCodeRequestAuthenticationToken(this.authorizationUri, converted.getClientId(),
				browser == null ? UsernamePasswordAuthenticationToken.unauthenticated("anonymous", null) : browser,
				converted.getRedirectUri(), converted.getState(), converted.getScopes(), converted.getAdditionalParameters());
		// The issuer comes from settings; Host and forwarding headers cannot select protocol identity.
		request.setAttribute(ORIGINAL, original);
		return original;
	}

	public View find(String handle, HttpServletRequest request) {
		try {
			var browser = currentBrowser(request);
			var pending = this.interactions.find(owner(request, false), handle).orElseThrow(() -> rejected(request, 400, "invalid_request"));
			var original = pending.request();
			var client = this.clients.findActiveById(original.clientId().toString()).filter(value -> value.registration().getRedirectUris().contains(original.redirectUri())
					&& value.registration().getScopes().containsAll(original.scopes())).orElseThrow(() -> rejected(request, 400, "invalid_request"));
			var evidence = evidence(request);
			var prompts = Set.copyOf(java.util.Arrays.asList(original.parameters().getOrDefault("prompt", "").split(" ")));
			return new View(original.clientId(), client.client().configuration().displayName(), original.scopes().stream().sorted().toList(), pending.expiresAt(),
					browser == null ? null : (UUID) browser.getPrincipal(), this.provider.requiresLogin(pending, browser == null ? null : Instant.ofEpochMilli(evidence.authenticatedAt())),
					prompts.contains("select_account"), prompts.contains("consent"));
		}
		catch (Failure ex) { throw ex; }
		catch (RuntimeException ex) { throw rejected(request, 503, "server_error"); }
	}

	public String complete(String handle, String decision, HttpServletRequest request) {
		try {
			if ("cancel".equals(decision)) {
				var denied = this.provider.deny(owner(request, false), handle, IdentityBrowserDiagnostics.correlationId(request));
				return redirect(denied.redirectUri(), "error", "access_denied", denied.state());
			}
			if (!"continue".equals(decision)) { throw rejected(request, 400, "invalid_request"); }
			var browser = currentBrowser(request);
			var result = this.provider.resume(owner(request, false), handle, browser, evidence(request));
			return redirect(result.getRedirectUri(), "code", result.getAuthorizationCode().getTokenValue(), result.getState());
		}
		catch (Failure ex) { throw ex; }
		catch (OAuth2AuthenticationException ex) { throw protocolFailure(ex); }
		catch (RuntimeException ex) { throw rejected(request, 503, "server_error"); }
	}

	public record View(UUID clientId, String clientName, List<String> scopes, Instant expiresAt, UUID subject,
			boolean loginRequired, boolean selectionRequired, boolean consentRequired) { }

	private void authorizationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException {
		if (!(request.getAttribute(ORIGINAL) instanceof OAuth2AuthorizationCodeRequestAuthenticationToken original)
				|| !(failure instanceof OAuth2AuthorizationCodeRequestAuthenticationException protocol)) {
			writeFailure(response, rejected(request, 400, "invalid_request")); return;
		}
		String code = protocol.getError().getErrorCode();
		if (Set.of("login_required", "consent_required", "account_selection_required").contains(code) && !promptNone(original)) {
			try {
				var ticket = this.provider.begin(original, owner(request, true));
				response.sendRedirect(UriComponentsBuilder.fromUriString(this.frontend).queryParam("interaction", ticket.handle()).build(true).toUriString());
			}
			catch (OAuth2AuthenticationException ex) { writeFailure(response, protocolFailure(ex)); }
			catch (RuntimeException ex) { writeFailure(response, rejected(request, 503, "server_error")); }
			return;
		}
		var safe = protocol.getAuthorizationCodeRequestAuthentication();
		if (safe == null || "server_error".equals(code) || "temporarily_unavailable".equals(code)) { writeFailure(response, protocolFailure(protocol)); return; }
		response.sendRedirect(redirect(safe.getRedirectUri(), "error", code, safe.getState()));
	}

	private Authentication currentBrowser(HttpServletRequest request) {
		var authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !(authentication.getPrincipal() instanceof UUID userId)) { return null; }
		var session = request.getSession(false);
		if (!authentication.isAuthenticated() || session == null || !this.sessions.isAuthenticationCurrent(userId,
				session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT), session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION))) {
			SecurityContextHolder.clearContext(); if (session != null) { session.invalidate(); } return null;
		}
		return UsernamePasswordAuthenticationToken.authenticated(userId, null, List.of());
	}

	private IdentityAuthorizationRequestProvider.BrowserEvidence evidence(HttpServletRequest request) {
		var session = request.getSession(false);
		return new IdentityAuthorizationRequestProvider.BrowserEvidence(session == null ? null : session.getId(),
				session != null && session.getAttribute(IdentityBrowserSessions.AUTHENTICATED_AT) instanceof Long time ? time : 0,
				session != null && session.getAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION) instanceof Long version ? version : 0,
				IdentityBrowserDiagnostics.correlationId(request));
	}

	private String owner(HttpServletRequest request, boolean create) {
		var session = request.getSession(create);
		if (session == null) { return null; }
		if (session.getAttribute(OWNER) instanceof String value) { return value; }
		if (!create) { return null; }
		String value = this.interactions.browserOwner(session.getId()); session.setAttribute(OWNER, value); return value;
	}

	/** Used only before a trusted provider has already recorded the rejection. */
	public Failure rejected(HttpServletRequest request, int status, String code) {
		try { this.transaction.executeWithoutResult(tx -> this.audits.recordFailure(Action.AUTHORIZATION_REQUEST_REJECTED, null,
				new SecurityAuditContext("anonymous", "protocol:authorize", IdentityBrowserDiagnostics.correlationId(request)))); }
		catch (RuntimeException ex) { return new Failure(503, "server_error"); }
		return new Failure(status, code);
	}

	public void writeFailure(HttpServletResponse response, Failure failure) throws IOException { IdentityProtocolResponses.error(response, failure.status(), failure.code()); }

	private static Failure protocolFailure(OAuth2AuthenticationException exception) {
		String code = exception.getError().getErrorCode();
		int status = switch (code) { case "server_error" -> 503; case "temporarily_unavailable" -> 429; case "login_required" -> 401; default -> 400; };
		return new Failure(status, code);
	}

	public static final class Failure extends RuntimeException {
		private final int status; private final String code;
		private Failure(int status, String code) { super("Authorization endpoint rejected the request"); this.status = status; this.code = code; }
		public int status() { return this.status; }
		public String code() { return this.code; }
	}

	private static boolean promptNone(OAuth2AuthorizationCodeRequestAuthenticationToken request) {
		return request.getAdditionalParameters().get("prompt") instanceof String prompt && Set.copyOf(java.util.Arrays.asList(prompt.split(" "))).contains("none");
	}

	private static String redirect(String uri, String parameter, String value, String state) {
		var builder = UriComponentsBuilder.fromUriString(uri).queryParam(parameter, value);
		if (state != null) { builder.queryParam("state", UriUtils.encode(state, StandardCharsets.UTF_8)); }
		return builder.build(true).toUriString();
	}

	private static String requireFrontend(String issuer, String value) {
		try {
			if (value == null || value.length() > 2048) { throw new IllegalArgumentException(); }
			var front = URI.create(IdentityTokenRequests.requireIssuer(value)); var base = URI.create(issuer);
			if (!base.getHost().equalsIgnoreCase(front.getHost()) || port(base) != port(front)
					|| front.getPath() != null && front.getPath().chars().anyMatch(character -> character < 0x20 || character == 0x7f)) { throw new IllegalArgumentException(); }
			return value;
		}
		catch (IllegalArgumentException ex) { throw new IllegalArgumentException("A fixed same-origin HTTPS identity frontend URI is required"); }
	}
	private static int port(URI value) { return value.getPort() == -1 ? 443 : value.getPort(); }

}
