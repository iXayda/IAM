package com.ixayda.iam.client;

import java.time.Duration;
import java.util.Objects;

public record ClientTokenPolicy(Duration authorizationCodeTtl, Duration accessTokenTtl,
		boolean refreshTokensEnabled, Duration refreshTokenTtl) {

	private static final Duration MIN_AUTHORIZATION_CODE_TTL = Duration.ofSeconds(30);

	private static final Duration MAX_AUTHORIZATION_CODE_TTL = Duration.ofMinutes(10);

	private static final Duration MIN_ACCESS_TOKEN_TTL = Duration.ofMinutes(1);

	private static final Duration MAX_ACCESS_TOKEN_TTL = Duration.ofHours(1);

	private static final Duration MIN_REFRESH_TOKEN_TTL = Duration.ofMinutes(5);

	private static final Duration MAX_REFRESH_TOKEN_TTL = Duration.ofDays(30);

	public ClientTokenPolicy(Duration authorizationCodeTtl, Duration accessTokenTtl) {
		this(authorizationCodeTtl, accessTokenTtl, false, Duration.ofHours(1));
	}

	public ClientTokenPolicy {
		authorizationCodeTtl = validateTtl(authorizationCodeTtl, MIN_AUTHORIZATION_CODE_TTL,
				MAX_AUTHORIZATION_CODE_TTL,
				"Authorization code TTL");
		accessTokenTtl = validateTtl(accessTokenTtl, MIN_ACCESS_TOKEN_TTL, MAX_ACCESS_TOKEN_TTL,
				"Access token TTL");
		refreshTokenTtl = validateTtl(refreshTokenTtl, MIN_REFRESH_TOKEN_TTL, MAX_REFRESH_TOKEN_TTL,
				"Refresh token TTL");
		if (refreshTokensEnabled && refreshTokenTtl.compareTo(accessTokenTtl) <= 0) {
			throw new IllegalArgumentException("Refresh token TTL must be longer than the access token TTL");
		}
	}

	public static ClientTokenPolicy secureDefaults() {
		return new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5));
	}

	public static ClientTokenPolicy refreshEnabledDefaults() {
		return new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true, Duration.ofHours(1));
	}

	private static Duration validateTtl(Duration value, Duration minimum, Duration maximum, String name) {
		Objects.requireNonNull(value, name + " must not be null");
		if (value.getNano() != 0 || value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
			throw new IllegalArgumentException(
					name + " must be a whole number of seconds between " + minimum + " and " + maximum);
		}
		return value;
	}

}
