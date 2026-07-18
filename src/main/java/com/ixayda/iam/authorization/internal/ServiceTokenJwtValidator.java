package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import com.ixayda.iam.client.ClientIdentifier;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

final class ServiceTokenJwtValidator implements OAuth2TokenValidator<Jwt> {

	static final Duration MAX_TOKEN_LIFETIME = Duration.ofMinutes(5);

	static final Duration ALLOWED_CLOCK_SKEW = Duration.ofSeconds(30);

	private static final OAuth2Error INVALID_TOKEN = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
			"The service token claims are invalid.", null);

	private final String audience;

	private final Clock clock;

	ServiceTokenJwtValidator(URI audience) {
		this(audience, Clock.systemUTC());
	}

	ServiceTokenJwtValidator(URI audience, Clock clock) {
		this.audience = Objects.requireNonNull(audience, "Service token audience must not be null").toASCIIString();
		this.clock = Objects.requireNonNull(clock, "Service token validation clock must not be null");
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Objects.requireNonNull(token, "Service token must not be null");
		Instant issuedAt = token.getIssuedAt();
		Instant expiresAt = token.getExpiresAt();
		List<String> audiences = token.getAudience();
		if (issuedAt == null || expiresAt == null || !expiresAt.isAfter(issuedAt)
				|| Duration.between(issuedAt, expiresAt).compareTo(MAX_TOKEN_LIFETIME) > 0
				|| issuedAt.isAfter(this.clock.instant().plus(ALLOWED_CLOCK_SKEW))
				|| audiences == null || !audiences.equals(List.of(this.audience))) {
			return invalid();
		}

		Object tenantClaim = token.getClaims().get(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM);
		if (!(tenantClaim instanceof String tenantId) || !isCanonicalUuid(tenantId)) {
			return invalid();
		}

		Object clientClaim = token.getClaims().get(ServiceTokenJwtCustomizer.CLIENT_ID_CLAIM);
		Object subjectClaim = token.getClaims().get("sub");
		if (!(clientClaim instanceof String clientId) || !(subjectClaim instanceof String subject)
				|| !isValidClientIdentifier(clientId) || !clientId.equals(subject)) {
			return invalid();
		}
		return OAuth2TokenValidatorResult.success();
	}

	private static boolean isCanonicalUuid(String value) {
		try {
			return UUID.fromString(value).toString().equals(value);
		}
		catch (IllegalArgumentException exception) {
			return false;
		}
	}

	private static boolean isValidClientIdentifier(String value) {
		try {
			new ClientIdentifier(value);
			return true;
		}
		catch (NullPointerException | IllegalArgumentException exception) {
			return false;
		}
	}

	private static OAuth2TokenValidatorResult invalid() {
		return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
	}

}
