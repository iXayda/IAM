package com.ixayda.iam.security;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAuthorizationSession;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizationSessions;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.SecurityAudits;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Explicit code-request adapter; the HTTP chain must replace its native provider, never retain a permissive fallback. */
public final class IdentityAuthorizationRequestProvider implements AuthenticationProvider {

	private static final Set<String> PARAMETERS = Set.of("code_challenge", "code_challenge_method", "nonce", "prompt", "max_age", "response_mode");
	private static final Set<String> UNSUPPORTED_PARAMETERS = Set.of("request", "request_uri", "resource", "audience");
	private static final OAuth2AuthorizationConsentService PREAUTHORIZED = new OAuth2AuthorizationConsentService() {
		@Override public void save(OAuth2AuthorizationConsent consent) { throw new IllegalStateException("Interactive consent must use its bound workflow"); }
		@Override public void remove(OAuth2AuthorizationConsent consent) { throw new IllegalStateException("Interactive consent must use its bound workflow"); }
		@Override public OAuth2AuthorizationConsent findById(String client, String principal) { return null; }
	};
	private final IdentityProtocolClients clients;
	private final IdentityAuthorizationSessions sessions;
	private final IdentityAuthorizationBindings bindings;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	public IdentityAuthorizationRequestProvider(IdentityProtocolClients clients, IdentityAuthorizationSessions sessions,
			IdentityAuthorizationBindings bindings, SecurityAudits audits, PlatformTransactionManager manager) {
		Assert.notNull(clients, "Protocol clients are required"); Assert.notNull(sessions, "Authorization sessions are required");
		Assert.notNull(bindings, "Authorization bindings are required"); Assert.notNull(audits, "Audits are required"); Assert.notNull(manager, "Transactions are required");
		this.clients = clients; this.sessions = sessions; this.bindings = bindings; this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken request)) { return null; }
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw failure("server_error", null); }
		var browser = request.getPrincipal() instanceof Authentication principal ? principal : null;
		UUID subject = browser != null && browser.isAuthenticated() && browser.getPrincipal() instanceof UUID id ? id : null;
		var details = request.getDetails() instanceof BrowserEvidence evidence ? evidence : null;
		var audit = new SecurityAuditContext(subject == null ? "anonymous" : "user:" + subject, "protocol:authorize",
				details == null ? UUID.randomUUID() : details.correlationId());
		OAuth2AuthorizationCodeRequestAuthenticationToken safe = null;
		try {
			var client = this.clients.findActiveById(request.getClientId()).orElseThrow(() -> failure("invalid_request", null));
			// Validate the exact string before constructing any redirectable error, including loopback HTTPS ports.
			if (request.getRedirectUri() == null || !client.registration().getRedirectUris().contains(request.getRedirectUri())) { throw failure("invalid_request", null); }
			validateAuthorizationUri(request.getAuthorizationUri());
			safe = safeRequest(request);
			var normalized = normalize(request);
			validate(normalized, client);
			if (subject == null || details == null || details.credentialVersion() < 1) { throw failure("login_required", safe); }
			var response = this.transaction.execute(status -> {
				var session = this.sessions.projectForIssuance(subject, details.sessionId(), details.authenticatedAt(), details.credentialVersion(), client)
						.orElseThrow(() -> failure("login_required", null));
				validateInteraction(normalized, session.authenticatedAt());
				var principal = this.bindings.projectPrincipal(session);
				var projected = new OAuth2AuthorizationCodeRequestAuthenticationToken(normalized.getAuthorizationUri(), normalized.getClientId(), principal,
						normalized.getRedirectUri(), normalized.getState(), normalized.getScopes(), normalized.getAdditionalParameters());
				var store = new CreationStore(session, audit);
				var provider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(IdentityRegisteredClientRepository.pinned(client), store, PREAUTHORIZED);
				provider.setAuthorizationConsentRequired(context -> false);
				var nativeResult = (OAuth2AuthorizationCodeRequestAuthenticationToken) provider.authenticate(projected);
				if (store.saved == null || nativeResult == null || nativeResult.getAuthorizationCode() == null) { throw failure("server_error", null); }
				var savedCode = store.saved.getToken(OAuth2AuthorizationCode.class).getToken();
				if (!nativeResult.getAuthorizationCode().getTokenValue().equals(savedCode.getTokenValue())) { throw failure("server_error", null); }
				validateInteraction(normalized, session.authenticatedAt());
				return new OAuth2AuthorizationCodeRequestAuthenticationToken(nativeResult.getAuthorizationUri(), nativeResult.getClientId(), principal,
						savedCode, nativeResult.getRedirectUri(), nativeResult.getState(), nativeResult.getScopes());
			});
			if (response == null) { throw failure("server_error", null); }
			return response;
		}
		catch (OAuth2AuthorizationCodeRequestAuthenticationException ex) { throw rejected(ex.getError().getErrorCode(), safe, subject, audit); }
		catch (IdentityAuthorizationBindings.ExpiredAuthorizationException ex) { throw rejected("login_required", safe, subject, audit); }
		catch (RuntimeException ex) { throw rejected("server_error", safe, subject, audit); }
	}

	@Override
	public boolean supports(Class<?> authentication) { return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication); }

	/** Server-created hints only; all facts are rechecked against persistent storage before issuance. */
	public record BrowserEvidence(String sessionId, long authenticatedAt, long credentialVersion, UUID correlationId) {
		public BrowserEvidence { Assert.notNull(correlationId, "Correlation id is required"); }
		@Override public String toString() { return "BrowserEvidence[REDACTED]"; }
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken normalize(OAuth2AuthorizationCodeRequestAuthenticationToken request) {
		var parameters = new HashMap<String, Object>();
		request.getAdditionalParameters().forEach((name, value) -> {
			// RFC 6749 section 3.1: reject duplicates, omit empty values and ignore unrecognized extensions.
			if (!(value instanceof String text)) { throw failure("invalid_request", null); }
			if (text.isEmpty()) { return; }
			if (UNSUPPORTED_PARAMETERS.contains(name)) { throw failure("invalid_request", null); }
			if (PARAMETERS.contains(name)) { parameters.put(name, text); }
		});
		return new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getAuthorizationUri(), request.getClientId(),
				(Authentication) request.getPrincipal(), request.getRedirectUri(), request.getState(), request.getScopes(), parameters);
	}

	private static void validate(OAuth2AuthorizationCodeRequestAuthenticationToken request, IdentityProtocolClients.Snapshot client) {
		if (!request.getScopes().contains("openid") || !client.registration().getScopes().containsAll(request.getScopes())) { throw failure("invalid_scope", null); }
		if (!boundedText(request.getState(), 512)) { throw failure("invalid_request", null); }
		var parameters = request.getAdditionalParameters();
		if (parameters.entrySet().stream().anyMatch(entry -> !(entry.getValue() instanceof String text)
				|| !(entry.getKey().equals("prompt") ? boundedPrompt(text) : boundedText(text, 512)))) {
			throw failure("invalid_request", null);
		}
		if (!"S256".equals(parameters.get("code_challenge_method")) || !(parameters.get("code_challenge") instanceof String challenge) || !canonicalChallenge(challenge)
				|| (parameters.containsKey("response_mode") && !"query".equals(parameters.get("response_mode")))) { throw failure("invalid_request", null); }
		if (parameters.containsKey("nonce") && !boundedText((String) parameters.get("nonce"), 256)) { throw failure("invalid_request", null); }
		if (parameters.containsKey("prompt")) {
			String prompt = (String) parameters.get("prompt");
			String[] prompts = prompt.split(" ", -1);
			var values = new java.util.HashSet<>(java.util.Arrays.asList(prompts));
			if (values.size() != prompts.length || !Set.of("none", "login", "consent", "select_account").containsAll(values)
					|| values.contains("none") && values.size() != 1) { throw failure("invalid_request", null); }
		}
		if (parameters.containsKey("max_age")) {
			try { maxAge((String) parameters.get("max_age")); }
			catch (IllegalArgumentException ex) { throw failure("invalid_request", null); }
		}
	}

	private static void validateInteraction(OAuth2AuthorizationCodeRequestAuthenticationToken request, Instant authenticatedAt) {
		var parameters = request.getAdditionalParameters();
		var prompts = Set.copyOf(java.util.Arrays.asList(((String) parameters.getOrDefault("prompt", "")).split(" ")));
		// Interactive requests must be resumed by a separately bound interaction workflow, never silently ignored.
		if (prompts.contains("login")) { throw failure("login_required", null); }
		if (prompts.contains("select_account")) { throw failure("account_selection_required", null); }
		if (prompts.contains("consent")) { throw failure("consent_required", null); }
		if (parameters.containsKey("max_age")) {
			long age = maxAge((String) parameters.get("max_age"));
			if (age == 0 || Instant.now().getEpochSecond() - authenticatedAt.getEpochSecond() >= age) { throw failure("login_required", null); }
		}
	}

	private static long maxAge(String value) {
		if (!value.matches("[0-9]{1,19}")) { throw new IllegalArgumentException("Invalid max_age"); }
		return Long.parseLong(value);
	}

	private static void validateAuthorizationUri(String authorizationUri) {
		var server = AuthorizationServerContextHolder.getContext();
		if (server == null || server.getAuthorizationServerSettings().getIssuer() == null
				|| !server.getAuthorizationServerSettings().getIssuer().equals(server.getIssuer())) { throw failure("server_error", null); }
		String issuer = server.getIssuer();
		var uri = java.net.URI.create(issuer);
		if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) { throw failure("server_error", null); }
		String expected = (issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer) + server.getAuthorizationServerSettings().getAuthorizationEndpoint();
		if (!expected.equals(authorizationUri)) { throw failure("invalid_request", null); }
	}

	private static boolean canonicalChallenge(String value) {
		if (!value.matches("[A-Za-z0-9_-]{43}")) { return false; }
		byte[] decoded = Base64.getUrlDecoder().decode(value);
		return decoded.length == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value);
	}

	private static boolean boundedText(String value, int maximum) {
		return value != null && !value.isEmpty() && value.length() <= maximum && value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e);
	}

	private static boolean boundedPrompt(String value) {
		return !value.isEmpty() && value.length() <= 512 && value.chars().allMatch(character -> character >= 0x20 && character <= 0x7e);
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken safeRequest(OAuth2AuthorizationCodeRequestAuthenticationToken request) {
		return new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getAuthorizationUri(), request.getClientId(),
				UsernamePasswordAuthenticationToken.unauthenticated("anonymous", null), request.getRedirectUri(),
				boundedText(request.getState(), 512) ? request.getState() : null, Set.of(), Map.of());
	}

	private OAuth2AuthorizationCodeRequestAuthenticationException rejected(String code, OAuth2AuthorizationCodeRequestAuthenticationToken safe, UUID subject, SecurityAuditContext audit) {
		try { this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.AUTHORIZATION_REQUEST_REJECTED, subject, audit)); }
		catch (RuntimeException ex) { return failure("server_error", safe); }
		return failure(code, safe);
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationException failure(String code, OAuth2AuthorizationCodeRequestAuthenticationToken request) {
		String description = switch (code) {
			case "invalid_request" -> "Authorization request is invalid";
			case "invalid_scope" -> "Authorization scope is invalid";
			case "login_required" -> "Authentication is required";
			case "consent_required" -> "Consent interaction is required";
			case "account_selection_required" -> "Account selection is required";
			default -> { code = "server_error"; yield "Authorization is unavailable"; }
		};
		return new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(code, description, null), request);
	}

	private final class CreationStore implements OAuth2AuthorizationService {
		private final IdentityAuthorizationSession session;
		private final SecurityAuditContext audit;
		private OAuth2Authorization saved;
		CreationStore(IdentityAuthorizationSession session, SecurityAuditContext audit) { this.session = session; this.audit = audit; }
		@Override public void save(OAuth2Authorization authorization) {
			if (this.saved != null) { throw new IllegalStateException("Authorization was already created"); }
			this.saved = IdentityAuthorizationRequestProvider.this.bindings.create(authorization, this.session, this.audit).authorization();
		}
		@Override public void remove(OAuth2Authorization authorization) { throw new IllegalStateException("Authorization creation cannot remove grants"); }
		@Override public OAuth2Authorization findById(String id) { throw new IllegalStateException("Authorization creation cannot read grants"); }
		@Override public OAuth2Authorization findByToken(String token, OAuth2TokenType type) { throw new IllegalStateException("Authorization creation cannot read grants"); }
	}

}
