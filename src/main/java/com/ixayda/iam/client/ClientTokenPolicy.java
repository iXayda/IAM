package com.ixayda.iam.client;

import java.time.Duration;
import java.util.Objects;

public record ClientTokenPolicy(Duration authorizationCodeTtl, Duration accessTokenTtl) {

	private static final Duration MIN_AUTHORIZATION_CODE_TTL = Duration.ofSeconds(30);

	private static final Duration MAX_AUTHORIZATION_CODE_TTL = Duration.ofMinutes(10);

	private static final Duration MIN_ACCESS_TOKEN_TTL = Duration.ofMinutes(1);

	private static final Duration MAX_ACCESS_TOKEN_TTL = Duration.ofHours(1);

	public ClientTokenPolicy {
		authorizationCodeTtl = validateTtl(authorizationCodeTtl, MIN_AUTHORIZATION_CODE_TTL,
				MAX_AUTHORIZATION_CODE_TTL,
				"Authorization code TTL");
		accessTokenTtl = validateTtl(accessTokenTtl, MIN_ACCESS_TOKEN_TTL, MAX_ACCESS_TOKEN_TTL,
				"Access token TTL");
	}

	public static ClientTokenPolicy secureDefaults() {
		return new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5));
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
