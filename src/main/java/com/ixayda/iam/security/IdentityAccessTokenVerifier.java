package com.ixayda.iam.security;

import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAccessToken;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;

/** Official signature validation composed with current online grant bounds; never conveys IAM management authority. */
public final class IdentityAccessTokenVerifier {

	private final IdentityAccessTokens tokens;
	private final String issuer;

	public IdentityAccessTokenVerifier(IdentityAccessTokens tokens, String issuer) {
		Assert.notNull(tokens, "Online token gate is required");
		this.tokens = tokens; this.issuer = requireIssuer(issuer);
	}

	public Optional<IdentityAccessToken> verify(String raw) { return verify(raw, null); }

	/** Resource identity must come from the authenticated resource credential, never bearer claims or request fields. */
	public Optional<IdentityAccessToken> verifyForResource(String raw, UUID resourceId) {
		Assert.notNull(resourceId, "Authenticated resource is required"); return verify(raw, resourceId);
	}

	private Optional<IdentityAccessToken> verify(String raw, UUID resourceId) {
		var candidate = parse(raw); if (candidate.isEmpty()) { return Optional.empty(); }
		var parsed = candidate.orElseThrow();
		try {
			return resourceId == null ? this.tokens.use(raw, parsed.keyId(), context -> validate(raw, parsed.claims(), context))
					: this.tokens.useForResource(raw, parsed.keyId(), resourceId, context -> validate(raw, parsed.claims(), context));
		}
		catch (InvalidAccessTokenException ex) { return Optional.empty(); }
	}

	private IdentityAccessToken validate(String raw, Map<String, Object> claims, IdentityAccessTokens.Context context) {
		try {
			var decoder = NimbusJwtDecoder.withPublicKey(context.key().publicKey()).signatureAlgorithm(SignatureAlgorithm.RS256).validateType(false).build();
			var type = new JwtTypeValidator("at+jwt"); type.setAllowEmpty(false);
			var timestamp = new JwtTimestampValidator(Duration.ofSeconds(30));
			timestamp.setAllowEmptyExpiryClaim(false); timestamp.setAllowEmptyNotBeforeClaim(false);
			decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(type, new JwtIssuerValidator(this.issuer), timestamp));
			decoder.decode(raw);
		}
		catch (JwtException ex) { throw rejected(); }
		var token = context.token(); var access = token.access();
		if (!this.issuer.equals(claims.get("iss")) || !access.userId().toString().equals(claims.get("sub"))
				|| !access.clientId().toString().equals(claims.get("client_id")) || !token.authorizationId().toString().equals(claims.get("authorization_id"))
				|| !(List.of(access.audience()).equals(claims.get("aud")) || access.audience().equals(claims.get("aud")))
				|| !(claims.get("scope") instanceof String scope) || !matchesValues(java.util.Arrays.asList(scope.split(" ", -1)), token.scopes())
				|| !matchesValues(claims.get("roles"), Set.copyOf(access.roles().stream().map(role -> role.code()).toList()))
				|| canonicalId(claims.get("jti")).isEmpty()) { throw rejected(); }
		Instant issued = numericDate(claims.get("iat")); Instant expiry = numericDate(claims.get("exp"));
		if (!issued.equals(token.issuedAt().truncatedTo(ChronoUnit.SECONDS)) || !issued.equals(numericDate(claims.get("nbf")))
				|| !expiry.equals(token.expiresAt().truncatedTo(ChronoUnit.SECONDS)) || !expiry.isAfter(issued)
				|| expiry.isAfter(issued.plusSeconds(300)) || issued.isAfter(Instant.now().plusSeconds(30))) { throw rejected(); }
		return token;
	}

	private static boolean matchesValues(Object raw, Set<String> expected) {
		if (!(raw instanceof List<?> values) || !values.stream().allMatch(String.class::isInstance)) { return false; }
		var unique = Set.copyOf(values);
		return unique.size() == values.size() && expected.equals(unique);
	}

	private static Optional<Candidate> parse(String raw) {
		if (raw == null || raw.length() > 16_384 || !raw.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) { return Optional.empty(); }
		try {
			var jwt = SignedJWT.parse(raw); var header = jwt.getHeader(); var key = canonicalId(header.getKeyID());
			if (!JWSAlgorithm.RS256.equals(header.getAlgorithm()) || header.getType() == null || !"at+jwt".equals(header.getType().toString())
					|| !Set.of("alg", "typ", "kid").containsAll(header.getIncludedParams()) || key.isEmpty()) { return Optional.empty(); }
			var claims = jwt.getPayload().toJSONObject(); if (claims == null) { return Optional.empty(); }
			return Optional.of(new Candidate(key.orElseThrow(), claims));
		}
		catch (ParseException | IllegalArgumentException ex) { return Optional.empty(); }
	}

	private static Optional<UUID> canonicalId(Object raw) {
		if (!(raw instanceof String value)) { return Optional.empty(); }
		try { var id = UUID.fromString(value); return id.toString().equals(value) ? Optional.of(id) : Optional.empty(); }
		catch (IllegalArgumentException ex) { return Optional.empty(); }
	}

	private static Instant numericDate(Object raw) {
		if (!(raw instanceof Long || raw instanceof Integer)) { throw rejected(); }
		try { return Instant.ofEpochSecond(((Number) raw).longValue()); }
		catch (java.time.DateTimeException ex) { throw rejected(); }
	}

	private static String requireIssuer(String value) {
		try {
			var uri = URI.create(value);
			if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
					|| uri.getPort() == 0 || uri.getPort() > 65535 || uri.getPort() < -1 || uri.getRawAuthority().endsWith(":")) {
				throw new IllegalArgumentException("An explicit HTTPS issuer is required");
			}
			return value;
		}
		catch (IllegalArgumentException | NullPointerException ex) { throw new IllegalArgumentException("An explicit HTTPS issuer is required"); }
	}

	private static InvalidAccessTokenException rejected() { return new InvalidAccessTokenException(); }
	private static final class InvalidAccessTokenException extends RuntimeException { }
	private record Candidate(UUID keyId, Map<String, Object> claims) {
		@Override public String toString() { return "AccessTokenCandidate[REDACTED]"; }
	}

}
