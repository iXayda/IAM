package com.ixayda.iam.service;

import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAccessToken;
import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentitySigningKey;

import org.springframework.context.annotation.Lazy;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Current grant gate; a trusted protocol adapter verifies JWT purpose and claims while the returned bounds remain locked. */
@Service
@Lazy
public class IdentityAccessTokens {

	private final IdentitySigningKeys keys;
	private final IdentityApplicationRoles applications;
	private final IdentityProtocolClients clients;
	private final IdentityAuthorizations authorizations;
	private final IdentityAuthorizationBindings bindings;
	private final IdentityRefreshTokens refresh;
	private final TransactionTemplate transaction;

	IdentityAccessTokens(IdentitySigningKeys keys, IdentityApplicationRoles applications, IdentityProtocolClients clients, IdentityAuthorizations authorizations,
			IdentityAuthorizationBindings bindings, IdentityRefreshTokens refresh, PlatformTransactionManager manager) {
		this.keys = keys; this.applications = applications; this.clients = clients; this.authorizations = authorizations; this.bindings = bindings; this.refresh = refresh;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	/** UserInfo adapters separately require openid and project only actual scopes; no management authorization is conveyed. */
	public <T> Optional<T> use(String token, UUID keyId, Function<Context, T> validation) {
		return use(token, keyId, null, validation);
	}

	/** The resource identity comes from the authenticated resource, never from the presented token's audience. */
	public <T> Optional<T> useForResource(String token, UUID keyId, UUID resourceId, Function<Context, T> validation) {
		Assert.notNull(resourceId, "Authenticated resource is required");
		return use(token, keyId, resourceId, validation);
	}

	private <T> Optional<T> use(String token, UUID keyId, UUID resourceId, Function<Context, T> validation) {
		Assert.notNull(keyId, "Signing key id is required"); Assert.notNull(validation, "Trusted token validation is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Online token use requires an independent transaction"); }
		var hint = this.authorizations.findByToken(token, "access_token");
		if (hint.isEmpty()) { return Optional.empty(); }
		var original = this.bindings.findByAuthorization(hint.orElseThrow().authorization());
		if (original.isEmpty() || resourceId != null && !original.orElseThrow().session().access().resourceId().equals(resourceId)) { return Optional.empty(); }
		var binding = original.orElseThrow();
		var client = this.clients.findActiveById(binding.session().access().clientId().toString());
		if (client.isEmpty()) { return Optional.empty(); }
		try {
			var result = this.transaction.execute(status -> validate(token, keyId, binding, client.orElseThrow(), resourceId != null, validation));
			if (result == null) { throw new IllegalStateException("Token validation transaction returned no result"); }
			return result;
		}
		catch (ExpiredAccessException ex) { return Optional.empty(); }
	}

	private <T> Optional<T> validate(String token, UUID keyId, IdentityAuthorizationBinding original, IdentityProtocolClients.Snapshot client, boolean resourceValidation, Function<Context, T> validation) {
		var key = this.keys.lockForValidation(keyId);
		if (key.isEmpty()) { return Optional.empty(); }
		var access = this.applications.projectForUse(original.session().access().userId(), original.session().access().credentialVersion(), client);
		if (access.filter(original.session().access()::equals).isEmpty()) { return Optional.empty(); }
		var current = this.authorizations.lockForUse(original.id());
		if (current.isEmpty()) { return Optional.empty(); }
		var authorization = current.orElseThrow().authorization();
		if (this.bindings.findByAuthorization(authorization).filter(original::equals).isEmpty()) { return Optional.empty(); }
		if (IdentityAuthorizations.isRevoked(authorization)) { return Optional.empty(); }
		var bearer = authorization.getAccessToken();
		if (bearer == null || !bearer.isActive() || !bearer.getToken().getTokenValue().equals(token)) { return Optional.empty(); }
		var code = authorization.getToken(OAuth2AuthorizationCode.class);
		if (code == null || !code.isInvalidated()) { throw new IllegalStateException("Access token has no consumed authorization code"); }
		var actual = bearer.getToken(); var scopes = actual.getScopes();
		if (!original.scopes().containsAll(scopes) || actual.getIssuedAt().isBefore(original.issuedAt().truncatedTo(ChronoUnit.SECONDS))
				|| actual.getExpiresAt().isAfter(original.issuedAt().plus(30, ChronoUnit.DAYS))) { throw new IllegalStateException("Access token exceeds its original bounds"); }
		var family = this.refresh.findByAuthorization(authorization);
		if (family.isPresent()) {
			var found = family.orElseThrow();
			if (found.status() != IdentityRefreshFamily.Status.ACTIVE && found.status() != IdentityRefreshFamily.Status.CLOSED) { return Optional.empty(); }
			if (!found.scopes().equals(scopes)) { throw new IllegalStateException("Access token does not match current refresh scopes"); }
		}
		else if (!original.scopes().equals(scopes) || original.scopes().contains("offline_access")) { throw new IllegalStateException("Access token is missing its refresh bounds"); }
		var projected = new IdentityAccessToken(original.id(), access.orElseThrow(), scopes, actual.getIssuedAt(), actual.getExpiresAt());
		// Resource caches and introspection must stop at the signed NumericDate, even when native storage retains microseconds.
		var expiry = resourceValidation ? projected.expiresAt().truncatedTo(ChronoUnit.SECONDS) : projected.expiresAt();
		if (!this.bindings.isWithinLifetime(projected.issuedAt(), expiry)) { return Optional.empty(); }
		T accepted = validation.apply(new Context(projected, key.orElseThrow()));
		if (accepted == null) { throw new IllegalStateException("Token validation returned no result"); }
		if (!this.bindings.isWithinLifetime(projected.issuedAt(), expiry)) { throw new ExpiredAccessException(); }
		return Optional.of(accepted);
	}

	public record Context(IdentityAccessToken token, IdentitySigningKey key) {
		@Override public String toString() { return "AccessTokenContext[REDACTED]"; }
	}

	private static final class ExpiredAccessException extends RuntimeException { }

}
