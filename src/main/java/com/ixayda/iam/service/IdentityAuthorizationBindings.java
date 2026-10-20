package com.ixayda.iam.service;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.CodeVerifiers;
import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.IdentityAuthorizationSession;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityAuthorizationBindingRepository;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Immutable protocol bounds are authenticated inside the protected native record and verified against the queryable binding. */
@Service
public class IdentityAuthorizationBindings {

	private static final String BINDING = "iam.authorizationBinding";
	private final IdentityAuthorizationBindingRepository repository;
	private final IdentityAuthorizations authorizations;
	private final SecurityAudits audits;

	IdentityAuthorizationBindings(IdentityAuthorizationBindingRepository repository, IdentityAuthorizations authorizations, SecurityAudits audits) {
		this.repository = repository; this.authorizations = authorizations; this.audits = audits;
	}

	/** The trusted workflow acquired this context in the same transaction, before any authorization locks. */
	@Transactional(propagation = Propagation.MANDATORY)
	public IdentityAuthorizations.Snapshot create(OAuth2Authorization authorization, IdentityAuthorizationSession session, SecurityAuditContext audit) {
		Assert.notNull(authorization, "Authorization is required"); Assert.notNull(session, "Authorization session is required"); Assert.notNull(audit, "Audit context is required");
		var nativeCode = authorization.getToken(OAuth2AuthorizationCode.class);
		if (nativeCode == null || !nativeCode.isActive() || authorization.getAccessToken() != null || authorization.getRefreshToken() != null || authorization.getToken(OidcIdToken.class) != null
				|| !authorization.getPrincipalName().equals(session.access().userId().toString())
				|| !authorization.getRegisteredClientId().equals(session.access().clientId().toString())) { throw new IllegalArgumentException("Initial authorization is invalid"); }
		Instant issuedAt = nativeCode.getToken().getIssuedAt().truncatedTo(ChronoUnit.MICROS);
		Instant expiry = nativeCode.getToken().getExpiresAt().truncatedTo(ChronoUnit.MICROS);
		if (expiry.isAfter(session.expiresAt())) { expiry = session.expiresAt(); }
		if (!expiry.isAfter(issuedAt)) { throw new ExpiredAuthorizationException(); }
		var code = new OAuth2AuthorizationCode(nativeCode.getToken().getTokenValue(), issuedAt, expiry);
		var binding = new IdentityAuthorizationBinding(UUID.fromString(authorization.getId()), session, authorization.getAuthorizedScopes(), issuedAt, expiry);
		var protectedRecord = OAuth2Authorization.from(authorization).token(code)
				.attribute(Principal.class.getName(), projectPrincipal(session)).attribute(BINDING, encode(binding, authorization)).build();
		var saved = this.authorizations.save(protectedRecord, 0);
		this.repository.insert(binding);
		this.audits.recordSuccess(Action.AUTHORIZATION_CODE_ISSUED, session.access().userId(), audit);
		if (!this.repository.isBeforeDeadline(expiry)) { throw new ExpiredAuthorizationException(); }
		return saved;
	}

	/** Loads original bounds, not current grant validity; every queryable field must match authenticated native state. */
	public Optional<IdentityAuthorizationBinding> findByAuthorization(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "Authorization is required");
		var binding = this.repository.findById(UUID.fromString(authorization.getId()));
		if (binding.isEmpty()) { return Optional.empty(); }
		var current = binding.orElseThrow(); var code = authorization.getToken(OAuth2AuthorizationCode.class);
		if (!encode(current, authorization).equals(authorization.getAttribute(BINDING))
				|| !current.session().access().userId().toString().equals(authorization.getPrincipalName())
				|| !current.session().access().clientId().toString().equals(authorization.getRegisteredClientId())
				|| !current.scopes().equals(authorization.getAuthorizedScopes()) || code == null
				|| !current.issuedAt().equals(code.getToken().getIssuedAt()) || !current.codeExpiresAt().equals(code.getToken().getExpiresAt())
				|| !projectPrincipal(current.session()).equals(authorization.getAttribute(Principal.class.getName()))) {
			throw new IllegalStateException("Authorization binding does not match protected state");
		}
		return binding;
	}

	/** Uses a canonical String principal for official Jackson round trips and never inherits browser management authorities. */
	public Authentication projectPrincipal(IdentityAuthorizationSession session) {
		var password = FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(session.authenticatedAt()).build();
		return UsernamePasswordAuthenticationToken.authenticated(session.access().userId().toString(), null, List.of(password));
	}

	/** Recheck proof in the grant transaction; native client authentication happened before these locks. */
	public boolean matchesExchangeProof(OAuth2Authorization authorization, String code, String redirectUri, String verifier) {
		var nativeCode = authorization.getToken(OAuth2AuthorizationCode.class);
		OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		return nativeCode != null && nativeCode.getToken().getTokenValue().equals(code) && request != null
				&& request.getRedirectUri().equals(redirectUri) && "S256".equals(request.getAdditionalParameters().get("code_challenge_method"))
				&& request.getAdditionalParameters().get("code_challenge") instanceof String challenge && CodeVerifiers.matchesS256(verifier, challenge);
	}

	public boolean isBeforeDeadline(Instant deadline) { return this.repository.isBeforeDeadline(deadline); }

	private static String encode(IdentityAuthorizationBinding binding, OAuth2Authorization authorization) {
		var session = binding.session(); var access = session.access();
		var value = new StringBuilder("iam:authorization-binding:v1|").append(binding.id()).append('|').append(access.userId()).append('|')
				.append(access.clientId()).append('|').append(access.resourceId()).append('|')
				.append(Base64.getUrlEncoder().withoutPadding().encodeToString(access.audience().getBytes(StandardCharsets.UTF_8))).append('|')
				.append(access.credentialVersion()).append('|').append(access.clientVersion()).append('|').append(access.resourceVersion()).append('|').append(access.assignmentVersion()).append('|')
				.append(session.browserSessionId()).append('|').append(session.authenticatedAt()).append('|').append(session.idleExpiresAt()).append('|').append(session.absoluteExpiresAt()).append('|')
				.append(String.join(",", binding.scopes().stream().sorted().toList())).append('|').append(binding.issuedAt()).append('|').append(binding.codeExpiresAt());
		access.roles().stream().sorted(Comparator.comparing(role -> role.id().toString()))
				.forEach(role -> value.append('|').append(role.id()).append(':').append(role.code()).append(':').append(role.version()));
		Object original = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		if (!(original instanceof OAuth2AuthorizationRequest request) || !AuthorizationGrantType.AUTHORIZATION_CODE.equals(request.getGrantType())
				|| !OAuth2AuthorizationResponseType.CODE.equals(request.getResponseType())
				|| !request.getClientId().equals(access.clientId().toString()) || !request.getScopes().equals(binding.scopes()) || !request.getAttributes().isEmpty()) {
			throw new IllegalStateException("Authorization binding does not match protected state");
		}
		value.append("|request:v1");
		for (String field : new String[] { request.getAuthorizationUri(), request.getClientId(), request.getRedirectUri(), request.getState(), request.getAuthorizationRequestUri() }) { appendField(value, field); }
		request.getAdditionalParameters().entrySet().stream().sorted(java.util.Map.Entry.comparingByKey()).forEach(entry -> {
			appendField(value, entry.getKey());
			if (!(entry.getValue() instanceof String text)) { throw new IllegalStateException("Authorization binding does not match protected state"); }
			appendField(value, text);
		});
		var code = authorization.getToken(OAuth2AuthorizationCode.class);
		if (code == null) { throw new IllegalStateException("Authorization binding does not match protected state"); }
		value.append("|code:v1"); appendField(value, code.getToken().getTokenValue());
		return value.toString();
	}

	private static void appendField(StringBuilder output, String field) {
		if (field == null) { throw new IllegalStateException("Authorization binding does not match protected state"); }
		output.append('|').append(Base64.getUrlEncoder().withoutPadding().encodeToString(field.getBytes(StandardCharsets.UTF_8)));
	}

	public static final class ExpiredAuthorizationException extends IllegalStateException {
		public ExpiredAuthorizationException() { super("Authorization deadline elapsed"); }
	}

}
