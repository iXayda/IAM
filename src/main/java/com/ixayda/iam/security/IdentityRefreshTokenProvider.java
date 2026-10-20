package com.ixayda.iam.security;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.IdentityApplicationRoles;
import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.IdentityRefreshTokens;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.SecurityAudits;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import static com.ixayda.iam.security.IdentityTokenRequests.client;
import static com.ixayda.iam.security.IdentityTokenRequests.failure;
import static com.ixayda.iam.security.IdentityTokenRequests.issuer;

/** Native refresh adapter; original browser expiry never limits an independent offline grant. */
public final class IdentityRefreshTokenProvider implements AuthenticationProvider {

	private final IdentityApplicationRoles applications;
	private final IdentityAuthorizations authorizations;
	private final IdentityAuthorizationBindings bindings;
	private final IdentityRefreshTokens refresh;
	private final IdentityJwtEncoder encoder;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	public IdentityRefreshTokenProvider(IdentityApplicationRoles applications, IdentityAuthorizations authorizations, IdentityAuthorizationBindings bindings,
			IdentityRefreshTokens refresh, IdentitySigningKeys keys, SecurityAudits audits, PlatformTransactionManager manager) {
		Assert.notNull(applications, "Application projection is required"); Assert.notNull(authorizations, "Protected authorizations are required");
		Assert.notNull(bindings, "Original bounds are required"); Assert.notNull(refresh, "Refresh families are required");
		Assert.notNull(keys, "Signing keys are required"); Assert.notNull(audits, "Audits are required"); Assert.notNull(manager, "Transactions are required");
		this.applications = applications; this.authorizations = authorizations; this.bindings = bindings; this.refresh = refresh;
		this.encoder = new IdentityJwtEncoder(keys); this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof OAuth2RefreshTokenAuthenticationToken request)) { return null; }
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw failure("server_error"); }
		UUID subject = null;
		var evidence = request.getDetails() instanceof RequestEvidence details ? details : new RequestEvidence(UUID.randomUUID());
		var audit = new SecurityAuditContext("anonymous", "protocol:token", evidence.correlationId());
		Decision decision;
		try {
			var client = client(request.getPrincipal());
			audit = new SecurityAuditContext("client:" + client.client().id(), "protocol:token", evidence.correlationId());
			validateParameters(request);
			var hint = this.refresh.findByToken(request.getRefreshToken()).orElseThrow(() -> failure("invalid_grant"));
			var initial = this.authorizations.findById(hint.authorizationId()).orElseThrow(() -> failure("invalid_grant"));
			if (!initial.authorization().getRegisteredClientId().equals(client.registration().getId())) { throw failure("invalid_grant"); }
			var original = this.bindings.findByAuthorization(initial.authorization()).orElseThrow(() -> failure("invalid_grant"));
			subject = original.session().access().userId();
			String issuer = issuer(initial.authorization()); var attribution = audit;
			decision = this.transaction.execute(status -> rotate(request, client, original, issuer, attribution));
			if (decision == null) { throw failure("server_error"); }
		}
		catch (OAuth2AuthenticationException ex) { throw rejected(ex.getError().getErrorCode(), subject, audit); }
		catch (RuntimeException ex) { throw rejected("server_error", subject, audit); }
		// The denial must leave the replay quarantine and mandatory failure audit committed.
		if (decision.replayed()) { throw failure("invalid_grant"); }
		return decision.response();
	}

	private Decision rotate(OAuth2RefreshTokenAuthenticationToken request, IdentityProtocolClients.Snapshot client,
			IdentityAuthorizationBinding original, String issuer, SecurityAuditContext audit) {
		var access = this.applications.projectForIssuance(original.session().access().userId(), original.session().access().credentialVersion(), client);
		if (access.filter(original.session().access()::equals).isEmpty()) { throw failure("invalid_grant"); }
		var locked = this.authorizations.lockForUse(original.id()).orElseThrow(() -> failure("invalid_grant"));
		if (this.bindings.findByAuthorization(locked.authorization()).filter(original::equals).isEmpty()) { throw failure("invalid_grant"); }
		var context = this.refresh.lockForUse(locked, request.getRefreshToken()).orElseThrow(() -> failure("invalid_grant"));
		if (context.requested().consumedAt() != null) {
			this.refresh.quarantine(locked);
			this.audits.recordFailure(Action.REFRESH_TOKEN_REPLAYED, original.session().access().userId(), audit);
			return new Decision(null, true);
		}
		var family = context.family();
		if (family.status() != IdentityRefreshFamily.Status.ACTIVE || !family.currentDigest().equals(context.requested().digest())
				|| !this.bindings.isBeforeDeadline(family.idleExpiresAt())) { throw failure("invalid_grant"); }
		Set<String> scopes = request.getScopes().isEmpty() ? family.scopes() : request.getScopes();
		if (!family.scopes().containsAll(scopes)) { throw failure("invalid_scope"); }
		var projectedClient = new OAuth2ClientAuthenticationToken(client.registration(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		var projected = new OAuth2RefreshTokenAuthenticationToken(request.getRefreshToken(), projectedClient, scopes, Map.of());
		var store = new RefreshStore(context, original, client, scopes);
		var provider = new OAuth2RefreshTokenAuthenticationProvider(store, new IdentityTokenGenerator(this.encoder, original, client, issuer));
		var nativeResponse = (OAuth2AccessTokenAuthenticationToken) provider.authenticate(projected);
		var response = store.response(nativeResponse, projectedClient);
		this.audits.recordSuccess(Action.TOKENS_REFRESHED, original.session().access().userId(), audit);
		Instant deadline = Stream.of(context.requested().expiresAt(), family.absoluteExpiresAt(), response.getAccessToken().getExpiresAt(),
				response.getRefreshToken() == null ? null : response.getRefreshToken().getExpiresAt(),
				scopes.contains("openid") ? store.saved.authorization().getToken(OidcIdToken.class).getToken().getExpiresAt() : null)
				.filter(java.util.Objects::nonNull).min(Instant::compareTo).orElseThrow();
		if (!this.bindings.isBeforeDeadline(deadline)) { throw failure("invalid_grant"); }
		return new Decision(response, false);
	}

	@Override
	public boolean supports(Class<?> authentication) { return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication); }

	public record RequestEvidence(UUID correlationId) {
		public RequestEvidence { Assert.notNull(correlationId, "Correlation id is required"); }
	}

	private record Decision(OAuth2AccessTokenAuthenticationToken response, boolean replayed) { }

	private static void validateParameters(OAuth2RefreshTokenAuthenticationToken request) {
		for (var entry : request.getAdditionalParameters().entrySet()) {
			if (!(entry.getValue() instanceof String text)) { throw failure("invalid_request"); }
			if (!text.isEmpty() && Set.of("scope", "resource", "audience", "request", "request_uri").contains(entry.getKey())) { throw failure("invalid_request"); }
		}
	}

	private OAuth2AuthenticationException rejected(String code, UUID subject, SecurityAuditContext audit) {
		try { this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.TOKEN_REQUEST_REJECTED, subject, audit)); }
		catch (RuntimeException ex) { return failure("server_error"); }
		return failure(code);
	}

	private final class RefreshStore implements OAuth2AuthorizationService {
		private final IdentityRefreshTokens.Context original;
		private final IdentityAuthorizationBinding binding;
		private final IdentityProtocolClients.Snapshot client;
		private final Set<String> scopes;
		private OAuth2Authorization issued;
		private IdentityAuthorizations.Snapshot saved;
		RefreshStore(IdentityRefreshTokens.Context original, IdentityAuthorizationBinding binding, IdentityProtocolClients.Snapshot client, Set<String> scopes) {
			this.original = original; this.binding = binding; this.client = client; this.scopes = scopes;
		}
		@Override public OAuth2Authorization findByToken(String value, OAuth2TokenType type) {
			var refresh = this.original.authorization().authorization().getRefreshToken();
			if (!OAuth2TokenType.REFRESH_TOKEN.equals(type) || !refresh.getToken().getTokenValue().equals(value)) { throw new IllegalStateException("Refresh lookup does not match its token"); }
			return this.original.authorization().authorization();
		}
		@Override public void save(OAuth2Authorization authorization) {
			if (this.saved != null || IdentityRefreshTokenProvider.this.bindings.findByAuthorization(authorization).filter(this.binding::equals).isEmpty()
					|| !authorization.getToken(OAuth2AuthorizationCode.class).isInvalidated() || authorization.getAccessToken() == null || !authorization.getAccessToken().isActive()
					|| authorization.getRefreshToken() == null || !authorization.getRefreshToken().isActive()
					|| authorization.getToken(OidcIdToken.class) == null || !authorization.getToken(OidcIdToken.class).isActive()) { throw new IllegalStateException("Refresh result is invalid"); }
			this.issued = authorization;
			// Preserve immutable original scopes and token metadata; no reflective removal or synthetic client/grant type.
			var projected = OAuth2Authorization.withRegisteredClient(this.client.registration()).id(authorization.getId()).principalName(authorization.getPrincipalName())
					.authorizationGrantType(authorization.getAuthorizationGrantType()).authorizedScopes(authorization.getAuthorizedScopes()).attributes(values -> values.putAll(authorization.getAttributes()));
			copyToken(projected, authorization.getToken(OAuth2AuthorizationCode.class)); copyToken(projected, authorization.getAccessToken());
			if (this.scopes.contains("offline_access")) { copyToken(projected, authorization.getRefreshToken()); }
			// Native JwtGenerator needs the prior ID on subsequent refreshes. A removed openid scope never renews or returns that historical ID.
			copyToken(projected, this.scopes.contains("openid") ? authorization.getToken(OidcIdToken.class) : this.original.authorization().authorization().getToken(OidcIdToken.class));
			this.saved = IdentityRefreshTokenProvider.this.refresh.rotate(this.original, projected.build(), authorization.getRefreshToken().getToken(), this.scopes);
		}
		OAuth2AccessTokenAuthenticationToken response(OAuth2AccessTokenAuthenticationToken nativeResponse, OAuth2ClientAuthenticationToken principal) {
			if (nativeResponse == null || this.saved == null || !this.issued.getAccessToken().getToken().equals(nativeResponse.getAccessToken())
					|| !this.issued.getRefreshToken().getToken().equals(nativeResponse.getRefreshToken())
					|| !this.issued.getToken(OidcIdToken.class).getToken().getTokenValue().equals(nativeResponse.getAdditionalParameters().get("id_token"))) {
				throw new IllegalStateException("Refresh response does not match persisted state");
			}
			var persisted = this.saved.authorization();
			return new OAuth2AccessTokenAuthenticationToken(this.client.registration(), principal, persisted.getAccessToken().getToken(),
					persisted.getRefreshToken() == null ? null : persisted.getRefreshToken().getToken(),
					this.scopes.contains("openid") ? Map.of("id_token", persisted.getToken(OidcIdToken.class).getToken().getTokenValue()) : Map.of());
		}
		@Override public void remove(OAuth2Authorization authorization) { throw new IllegalStateException("Refresh cannot remove grants"); }
		@Override public OAuth2Authorization findById(String id) { throw new IllegalStateException("Refresh cannot query other grants"); }
	}

	private static <T extends OAuth2Token> void copyToken(OAuth2Authorization.Builder builder, OAuth2Authorization.Token<T> token) {
		builder.token(token.getToken(), metadata -> metadata.putAll(token.getMetadata()));
	}

}
