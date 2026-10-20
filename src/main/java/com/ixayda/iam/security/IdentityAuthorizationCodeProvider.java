package com.ixayda.iam.security;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.IdentityApplicationRoles;
import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityAuthorizationSessions;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.IdentityRefreshTokens;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.SecurityAudits;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import static com.ixayda.iam.security.IdentityTokenRequests.client;
import static com.ixayda.iam.security.IdentityTokenRequests.failure;
import static com.ixayda.iam.security.IdentityTokenRequests.issuer;

/** Explicit native exchange adapter; grant state and mandatory audit commit before tokens or replay denial escape. */
public final class IdentityAuthorizationCodeProvider implements AuthenticationProvider {

	private final IdentityApplicationRoles applications;
	private final IdentityAuthorizationSessions sessions;
	private final IdentityAuthorizations authorizations;
	private final IdentityAuthorizationBindings bindings;
	private final IdentityRefreshTokens refresh;
	private final IdentityJwtEncoder encoder;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	public IdentityAuthorizationCodeProvider(IdentityApplicationRoles applications, IdentityAuthorizationSessions sessions,
			IdentityAuthorizations authorizations, IdentityAuthorizationBindings bindings, IdentityRefreshTokens refresh, IdentitySigningKeys keys,
			SecurityAudits audits, PlatformTransactionManager manager) {
		Assert.notNull(applications, "Application projection is required"); Assert.notNull(sessions, "Source sessions are required");
		Assert.notNull(authorizations, "Protected authorizations are required"); Assert.notNull(bindings, "Original bounds are required");
		Assert.notNull(refresh, "Refresh families are required");
		Assert.notNull(keys, "Signing keys are required"); Assert.notNull(audits, "Audits are required"); Assert.notNull(manager, "Transactions are required");
		this.applications = applications; this.sessions = sessions; this.authorizations = authorizations; this.bindings = bindings;
		this.refresh = refresh;
		this.encoder = new IdentityJwtEncoder(keys); this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof OAuth2AuthorizationCodeAuthenticationToken request)) { return null; }
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw failure("server_error"); }
		UUID subject = null;
		var evidence = request.getDetails() instanceof RequestEvidence details ? details : new RequestEvidence(UUID.randomUUID());
		var audit = new SecurityAuditContext("anonymous", "protocol:token", evidence.correlationId());
		Decision decision;
		try {
			var client = client(request.getPrincipal());
			audit = new SecurityAuditContext("client:" + client.client().id(), "protocol:token", evidence.correlationId());
			String verifier = verifier(request);
			var initial = this.authorizations.findByToken(request.getCode(), "code").orElseThrow(() -> failure("invalid_grant"));
			if (!initial.authorization().getRegisteredClientId().equals(client.registration().getId())) { throw failure("invalid_grant"); }
			var original = this.bindings.findByAuthorization(initial.authorization()).orElseThrow(() -> failure("invalid_grant"));
			subject = original.session().access().userId();
			String issuer = issuer(initial.authorization());
			var attribution = audit;
			decision = this.transaction.execute(status -> exchange(request, verifier, client, original, issuer, attribution));
			if (decision == null) { throw failure("server_error"); }
		}
		catch (OAuth2AuthenticationException ex) { throw rejected(ex.getError().getErrorCode(), subject, audit); }
		catch (RuntimeException ex) { throw rejected("server_error", subject, audit); }
		// Replay is a committed denial; throwing it inside the transaction would roll back the revocation.
		if (decision.replayed()) { throw failure("invalid_grant"); }
		return decision.response();
	}

	private Decision exchange(OAuth2AuthorizationCodeAuthenticationToken request, String verifier, IdentityProtocolClients.Snapshot client,
			IdentityAuthorizationBinding original, String issuer, SecurityAuditContext audit) {
		var access = this.applications.projectForIssuance(original.session().access().userId(), original.session().access().credentialVersion(), client);
		if (access.filter(original.session().access()::equals).isEmpty()) { throw failure("invalid_grant"); }
		var sourceDeadline = this.sessions.exchangeDeadline(original.session());
		var locked = this.authorizations.lockForUse(original.id()).orElseThrow(() -> failure("invalid_grant"));
		if (this.bindings.findByAuthorization(locked.authorization()).filter(original::equals).isEmpty()) { throw failure("invalid_grant"); }
		if (!this.bindings.matchesExchangeProof(locked.authorization(), request.getCode(), request.getRedirectUri(), verifier)) { throw failure("invalid_grant"); }
		var code = locked.authorization().getToken(OAuth2AuthorizationCode.class);
		if (code.isInvalidated()) {
			this.refresh.quarantine(locked);
			this.audits.recordFailure(Action.AUTHORIZATION_CODE_REPLAYED, original.session().access().userId(), audit);
			return new Decision(null, true);
		}
		if (locked.authorization().getAccessToken() != null || locked.authorization().getRefreshToken() != null || locked.authorization().getToken(OidcIdToken.class) != null) {
			throw failure("server_error");
		}
		if (sourceDeadline.isEmpty() || !code.isActive()) { throw failure("invalid_grant"); }
		var projectedClient = new OAuth2ClientAuthenticationToken(client.registration(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		var projected = new OAuth2AuthorizationCodeAuthenticationToken(request.getCode(), projectedClient, request.getRedirectUri(), Map.of("code_verifier", verifier));
		var store = new ExchangeStore(locked, original);
		var provider = new OAuth2AuthorizationCodeAuthenticationProvider(store, new IdentityTokenGenerator(this.encoder, original, client, issuer));
		var response = (OAuth2AccessTokenAuthenticationToken) provider.authenticate(projected);
		store.requireResult(response);
		this.audits.recordSuccess(Action.TOKENS_ISSUED, original.session().access().userId(), audit);
		Instant deadline = java.util.stream.Stream.of(original.codeExpiresAt(), sourceDeadline.orElseThrow(), response.getAccessToken().getExpiresAt(),
				store.saved.authorization().getToken(OidcIdToken.class).getToken().getExpiresAt()).min(Instant::compareTo).orElseThrow();
		if (!this.bindings.isBeforeDeadline(deadline)) { throw failure("invalid_grant"); }
		return new Decision(response, false);
	}

	@Override
	public boolean supports(Class<?> authentication) { return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication); }

	public record RequestEvidence(UUID correlationId) {
		public RequestEvidence { Assert.notNull(correlationId, "Correlation id is required"); }
	}

	private record Decision(OAuth2AccessTokenAuthenticationToken response, boolean replayed) { }

	private static String verifier(OAuth2AuthorizationCodeAuthenticationToken request) {
		for (var entry : request.getAdditionalParameters().entrySet()) {
			if (!(entry.getValue() instanceof String text)) { throw failure("invalid_request"); }
			if (!text.isEmpty() && Set.of("scope", "resource", "audience", "request", "request_uri").contains(entry.getKey())) { throw failure("invalid_request"); }
		}
		return request.getAdditionalParameters().get("code_verifier") instanceof String text ? text : null;
	}

	private OAuth2AuthenticationException rejected(String code, UUID subject, SecurityAuditContext audit) {
		try { this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.TOKEN_REQUEST_REJECTED, subject, audit)); }
		catch (RuntimeException ex) { return failure("server_error"); }
		return failure(code);
	}

	private final class ExchangeStore implements OAuth2AuthorizationService {
		private final IdentityAuthorizations.Snapshot original;
		private final IdentityAuthorizationBinding binding;
		private IdentityAuthorizations.Snapshot saved;
		ExchangeStore(IdentityAuthorizations.Snapshot original, IdentityAuthorizationBinding binding) { this.original = original; this.binding = binding; }
		@Override public OAuth2Authorization findByToken(String value, OAuth2TokenType type) {
			var code = this.original.authorization().getToken(OAuth2AuthorizationCode.class);
			if (type == null || !"code".equals(type.getValue()) || !code.getToken().getTokenValue().equals(value)) { throw new IllegalStateException("Exchange lookup does not match its code"); }
			return this.original.authorization();
		}
		@Override public void save(OAuth2Authorization authorization) {
			if (this.saved != null || IdentityAuthorizationCodeProvider.this.bindings.findByAuthorization(authorization).filter(this.binding::equals).isEmpty()
					|| !authorization.getToken(OAuth2AuthorizationCode.class).isInvalidated() || authorization.getAccessToken() == null || !authorization.getAccessToken().isActive()
					|| authorization.getToken(OidcIdToken.class) == null || !authorization.getToken(OidcIdToken.class).isActive()
					|| this.binding.scopes().contains("offline_access") != (authorization.getRefreshToken() != null)
					|| authorization.getRefreshToken() != null && !authorization.getRefreshToken().isActive()) { throw new IllegalStateException("Exchange result is invalid"); }
			this.saved = authorization.getRefreshToken() == null ? IdentityAuthorizationCodeProvider.this.authorizations.save(authorization, this.original.version())
					: IdentityAuthorizationCodeProvider.this.refresh.initialize(authorization, this.original.version(), this.binding);
		}
		void requireResult(OAuth2AccessTokenAuthenticationToken response) {
			if (response == null || this.saved == null || !this.saved.authorization().getAccessToken().getToken().equals(response.getAccessToken())
					|| !this.saved.authorization().getToken(OidcIdToken.class).getToken().getTokenValue().equals(response.getAdditionalParameters().get("id_token"))
					|| !java.util.Objects.equals(this.saved.authorization().getRefreshToken() == null ? null : this.saved.authorization().getRefreshToken().getToken(), response.getRefreshToken())) {
				throw new IllegalStateException("Exchange response does not match persisted state");
			}
		}
		@Override public void remove(OAuth2Authorization authorization) { throw new IllegalStateException("Exchange cannot remove grants"); }
		@Override public OAuth2Authorization findById(String id) { throw new IllegalStateException("Exchange cannot query other grants"); }
	}

}
