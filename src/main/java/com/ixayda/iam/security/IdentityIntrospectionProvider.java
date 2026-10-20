package com.ixayda.iam.security;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.IdentityResourceCredentials;
import com.ixayda.iam.service.SecurityAudits;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** One-resource introspection; native client registrations and browser authorities never grant access here. */
final class IdentityIntrospectionProvider implements AuthenticationProvider {

	private final IdentityAccessTokenVerifier verifier;
	private final IdentityResourceCredentials credentials;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;
	private final String issuer;

	IdentityIntrospectionProvider(IdentityAccessTokenVerifier verifier, IdentityResourceCredentials credentials,
			SecurityAudits audits, PlatformTransactionManager transactions, String issuer) {
		this.verifier = verifier; this.credentials = credentials; this.audits = audits; this.issuer = IdentityTokenRequests.requireIssuer(issuer);
		this.transaction = new TransactionTemplate(transactions);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	ResourceAuthentication authenticateResource(String id, String secret) {
		try { return new ResourceAuthentication(this.credentials.authenticate(id, secret).orElseThrow(() -> denied("invalid_client"))); }
		catch (OAuth2AuthenticationException ex) { throw ex; }
		catch (RuntimeException ex) { throw denied("server_error"); }
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof OAuth2TokenIntrospectionAuthenticationToken request)) { return null; }
		if (!(request.getPrincipal() instanceof ResourceAuthentication resource) || !resource.isAuthenticated()) { throw denied("invalid_client"); }
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Introspection requires an independent transaction"); }
		if (!(request.getDetails() instanceof Evidence evidence) || !request.getAdditionalParameters().isEmpty()) { throw denied("invalid_request"); }
		var snapshot = resource.snapshot;
		try {
			var active = this.verifier.useForResource(request.getToken(), snapshot.resource().id(), token -> {
				requireCurrent(snapshot);
				return OAuth2TokenIntrospection.builder().active(true).tokenType("Bearer").issuer(this.issuer)
						.subject(token.access().userId().toString()).clientId(token.access().clientId().toString()).audience(token.access().audience())
						.issuedAt(token.issuedAt().truncatedTo(ChronoUnit.SECONDS)).notBefore(token.issuedAt().truncatedTo(ChronoUnit.SECONDS))
						.expiresAt(token.expiresAt().truncatedTo(ChronoUnit.SECONDS)).scopes(scopes -> scopes.addAll(token.scopes().stream().sorted().toList()))
						.claim("roles", token.access().roles().stream().map(role -> role.code()).sorted().toList()).build();
			});
			var claims = active.orElseGet(() -> this.transaction.execute(status -> {
				requireCurrent(snapshot);
				this.audits.recordFailure(Action.INTROSPECTION_REJECTED, null,
						new SecurityAuditContext("resource:" + snapshot.resource().id(), "protocol:introspection", evidence.correlationId()));
				return OAuth2TokenIntrospection.builder().build();
			}));
			if (claims == null) { throw denied("server_error"); }
			return new OAuth2TokenIntrospectionAuthenticationToken(request.getToken(), resource, claims);
		}
		catch (OAuth2AuthenticationException ex) { throw ex; }
		catch (RuntimeException ex) { throw denied("server_error"); }
	}

	private void requireCurrent(IdentityResourceCredentials.Snapshot expected) {
		if (this.credentials.lockForValidation(expected).isEmpty()) { throw denied("invalid_client"); }
	}

	@Override
	public boolean supports(Class<?> authentication) { return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication); }

	private static OAuth2AuthenticationException denied(String code) { return new OAuth2AuthenticationException(code); }
	static record Evidence(UUID correlationId) { }

	static final class ResourceAuthentication extends AbstractAuthenticationToken {
		private final IdentityResourceCredentials.Snapshot snapshot;
		private ResourceAuthentication(IdentityResourceCredentials.Snapshot snapshot) { super(List.of()); this.snapshot = snapshot; super.setAuthenticated(true); }
		@Override public Object getPrincipal() { return this.snapshot.resource().id().toString(); }
		@Override public Object getCredentials() { return ""; }
		@Override public void setAuthenticated(boolean value) { if (value) { throw new IllegalArgumentException("Resource authentication requires credential verification"); } super.setAuthenticated(false); }
		@Override public String toString() { return "ResourceAuthentication[REDACTED]"; }
	}

}
