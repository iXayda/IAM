package com.ixayda.iam.ratelimit.internal;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.ratelimit.login")
record LoginRateLimitProperties(int principalLimit, Duration principalWindow, int sourceLimit, Duration sourceWindow,
		String keySecret, String keyPrefix) {

	private static final int MINIMUM_KEY_SECRET_BYTES = 32;

	private static final Duration MAXIMUM_WINDOW = Duration.ofDays(1);

	LoginRateLimitProperties(@DefaultValue("10") int principalLimit,
			@DefaultValue("1m") Duration principalWindow, @DefaultValue("50") int sourceLimit,
			@DefaultValue("1m") Duration sourceWindow, String keySecret,
			@DefaultValue("iam:ratelimit:login") String keyPrefix) {
		this.principalLimit = requirePositive(principalLimit, "Principal rate limit");
		this.principalWindow = requirePositiveMillis(principalWindow, "Principal rate-limit window");
		this.sourceLimit = requirePositive(sourceLimit, "Source rate limit");
		this.sourceWindow = requirePositiveMillis(sourceWindow, "Source rate-limit window");
		this.keySecret = keySecret;
		this.keyPrefix = validateKeyPrefix(keyPrefix);
		decodedKeySecret().ifPresent(secret -> Arrays.fill(secret, (byte) 0));
	}

	Optional<byte[]> decodedKeySecret() {
		if (!hasKeySecret()) {
			return Optional.empty();
		}
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(this.keySecret);
		}
		catch (IllegalArgumentException exception) {
			throw new IllegalArgumentException("Login rate-limit key secret must be valid Base64", exception);
		}
		if (decoded.length < MINIMUM_KEY_SECRET_BYTES) {
			throw new IllegalArgumentException("Login rate-limit key secret must contain at least 32 bytes");
		}
		return Optional.of(decoded);
	}

	boolean hasKeySecret() {
		return this.keySecret != null && !this.keySecret.isBlank();
	}

	@Override
	public String toString() {
		return "LoginRateLimitProperties[principalLimit=" + this.principalLimit + ", principalWindow="
				+ this.principalWindow + ", sourceLimit=" + this.sourceLimit + ", sourceWindow="
				+ this.sourceWindow + ", keySecret=redacted, keyPrefix=" + this.keyPrefix + "]";
	}

	private static int requirePositive(int value, String name) {
		if (value <= 0) {
			throw new IllegalArgumentException(name + " must be positive");
		}
		return value;
	}

	private static Duration requirePositiveMillis(Duration value, String name) {
		Objects.requireNonNull(value, name + " must not be null");
		if (value.compareTo(MAXIMUM_WINDOW) > 0) {
			throw new IllegalArgumentException(name + " must not exceed 24 hours");
		}
		long millis;
		try {
			millis = value.toMillis();
		}
		catch (ArithmeticException exception) {
			throw new IllegalArgumentException(name + " is too large", exception);
		}
		if (millis <= 0) {
			throw new IllegalArgumentException(name + " must be at least one millisecond");
		}
		return value;
	}

	private static String validateKeyPrefix(String value) {
		Objects.requireNonNull(value, "Login rate-limit key prefix must not be null");
		if (value.isEmpty() || value.length() > 64
				|| !value.chars().allMatch(character -> character >= 'a' && character <= 'z'
						|| character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
						|| character == ':' || character == '_' || character == '-')) {
			throw new IllegalArgumentException(
					"Login rate-limit key prefix must contain 1 to 64 letters, digits, colons, underscores, or hyphens");
		}
		return value;
	}

}
