package com.ixayda.iam.security;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.service.IdentityProtocolClients;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/** Per-grant official generators, constrained by original audience, scopes, roles and absolute lifetime. */
final class IdentityTokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

	private final IdentityAuthorizationBinding binding;
	private final IdentityProtocolClients.Snapshot client;
	private final String issuer;
	private final JwtGenerator jwt;
	private final OAuth2RefreshTokenGenerator refresh = new OAuth2RefreshTokenGenerator();

	IdentityTokenGenerator(JwtEncoder encoder, IdentityAuthorizationBinding binding, IdentityProtocolClients.Snapshot client, String issuer) {
		this.binding = binding; this.client = client; this.issuer = issuer;
		this.jwt = new JwtGenerator(encoder); this.jwt.setJwtCustomizer(this::customize);
	}

	@Override
	public OAuth2Token generate(OAuth2TokenContext context) {
		if (!this.client.registration().equals(context.getRegisteredClient()) || context.getAuthorizationServerContext() == null
				|| !this.issuer.equals(context.getAuthorizationServerContext().getIssuer())
				|| !this.binding.scopes().containsAll(context.getAuthorizedScopes())
				|| context.getAuthorization() == null || !this.binding.id().toString().equals(context.getAuthorization().getId())
				|| !this.binding.session().access().userId().toString().equals(context.getPrincipal().getName())) {
			throw new IllegalStateException("Token context does not match its authorization");
		}
		if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) { return this.jwt.generate(context); }
		if (!context.getAuthorizedScopes().contains("offline_access")) { return null; }
		var generated = this.refresh.generate(context);
		if (generated == null) { return null; }
		Instant issued = generated.getIssuedAt().truncatedTo(ChronoUnit.MICROS);
		Instant expiry = minimum(generated.getExpiresAt().truncatedTo(ChronoUnit.MICROS), issued.plus(7, ChronoUnit.DAYS), absoluteDeadline());
		if (!expiry.isAfter(issued)) { throw new IllegalStateException("Token lifetime has ended"); }
		return new OAuth2RefreshToken(generated.getTokenValue(), issued, expiry);
	}

	private void customize(JwtEncodingContext context) {
		boolean access = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
		Instant issued = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		Instant expiry = access ? minimum(issued.plusSeconds(300), issued.plus(context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive()), absoluteDeadline())
				: minimum(issued.plusSeconds(300), absoluteDeadline());
		if (!expiry.isAfter(issued)) { throw new IllegalStateException("Token lifetime has ended"); }
		var identity = this.binding.session().access();
		context.getJwsHeader().type(access ? "at+jwt" : "JWT");
		context.getClaims().issuer(this.issuer).subject(identity.userId().toString()).issuedAt(issued).expiresAt(expiry)
				.audience(List.of(access ? identity.audience() : identity.clientId().toString()));
		if (access) {
			context.getClaims().notBefore(issued).claim("client_id", identity.clientId().toString())
					.claim("authorization_id", this.binding.id().toString()).claim("scope", String.join(" ", context.getAuthorizedScopes().stream().sorted().toList()))
					.claim("roles", identity.roles().stream().map(role -> role.code()).sorted().toList());
		}
		else {
			context.getClaims().claim("auth_time", Date.from(this.binding.session().authenticatedAt().truncatedTo(ChronoUnit.SECONDS)));
		}
	}

	private Instant absoluteDeadline() { return this.binding.issuedAt().plus(30, ChronoUnit.DAYS); }
	private static Instant minimum(Instant... values) { return java.util.Arrays.stream(values).min(Instant::compareTo).orElseThrow(); }

}
