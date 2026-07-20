package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

final class AdminTokenJwtValidator implements OAuth2TokenValidator<Jwt> {

	static final Duration MAX_TOKEN_LIFETIME = Duration.ofHours(1);

	static final Duration ALLOWED_CLOCK_SKEW = Duration.ofSeconds(30);

	private static final OAuth2Error INVALID_TOKEN = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
			"The admin token claims are invalid.", null);

	private final String audience;

	private final Clock clock;

	AdminTokenJwtValidator(URI audience) {
		this(audience, Clock.systemUTC());
	}

	AdminTokenJwtValidator(URI audience, Clock clock) {
		this.audience = Objects.requireNonNull(audience, "Admin token audience must not be null").toASCIIString();
		this.clock = Objects.requireNonNull(clock, "Admin token validation clock must not be null");
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Objects.requireNonNull(token, "Admin token must not be null");
		Instant issuedAt = token.getIssuedAt();
		Instant expiresAt = token.getExpiresAt();
		Instant authenticatedAt = authenticationTime(token);
		if (issuedAt == null || expiresAt == null || !expiresAt.isAfter(issuedAt)
				|| Duration.between(issuedAt, expiresAt).compareTo(MAX_TOKEN_LIFETIME) > 0
				|| issuedAt.isAfter(this.clock.instant().plus(ALLOWED_CLOCK_SKEW))
				|| authenticatedAt == null || authenticatedAt.isAfter(issuedAt)
				|| !hasExactAudience(token)) {
			return invalid();
		}

		String tenantId = stringClaim(token, ServiceTokenJwtCustomizer.TENANT_ID_CLAIM);
		String userId = stringClaim(token, AdminTokenJwtCustomizer.USER_ID_CLAIM);
		String sessionId = stringClaim(token, AdminTokenJwtCustomizer.SESSION_ID_CLAIM);
		String subject = stringClaim(token, "sub");
		if (!isCanonicalUuid(tenantId) || !isCanonicalUuid(userId) || !isCanonicalUuid(sessionId)
				|| !userId.equals(subject) || !hasAdminScope(token)
				|| !isAuthenticationMethod(stringClaim(token,
						AdminTokenJwtCustomizer.AUTHENTICATION_METHOD_CLAIM))) {
			return invalid();
		}
		return OAuth2TokenValidatorResult.success();
	}

	private static boolean hasAdminScope(Jwt token) {
		Object scope = token.getClaims().get("scope");
		if (!(scope instanceof List<?> scopes) || scopes.isEmpty()) {
			return false;
		}
		return scopes.stream().allMatch(String.class::isInstance)
				&& scopes.contains(AdminTokenJwtCustomizer.ADMIN_SCOPE);
	}

	private boolean hasExactAudience(Jwt token) {
		Object audienceClaim = token.getClaims().get("aud");
		return audienceClaim instanceof List<?> audiences
				&& audiences.equals(List.of(this.audience));
	}

	private static Instant authenticationTime(Jwt token) {
		Object value = token.getClaims().get(AdminTokenJwtCustomizer.AUTHENTICATION_TIME_CLAIM);
		if (value instanceof Instant instant) {
			return instant;
		}
		if (!(value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte)) {
			return null;
		}
		try {
			return Instant.ofEpochSecond(((Number) value).longValue());
		}
		catch (DateTimeException | ArithmeticException exception) {
			return null;
		}
	}

	private static String stringClaim(Jwt token, String name) {
		Object value = token.getClaims().get(name);
		return value instanceof String string ? string : null;
	}

	private static boolean isCanonicalUuid(String value) {
		if (value == null) {
			return false;
		}
		try {
			return UUID.fromString(value).toString().equals(value);
		}
		catch (IllegalArgumentException exception) {
			return false;
		}
	}

	private static boolean isAuthenticationMethod(String value) {
		if (value == null || !value.equals(value.toLowerCase(Locale.ROOT))) {
			return false;
		}
		try {
			SessionAuthenticationMethod.valueOf(value.toUpperCase(Locale.ROOT));
			return true;
		}
		catch (IllegalArgumentException exception) {
			return false;
		}
	}

	private static OAuth2TokenValidatorResult invalid() {
		return OAuth2TokenValidatorResult.failure(INVALID_TOKEN);
	}

}
