package com.ixayda.iam.securitystate.internal;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.security-state")
record SecurityStateProperties(Duration maximumTtl, String keySecret, String keyPrefix) {

	private static final int MINIMUM_KEY_SECRET_BYTES = 32;

	private static final Duration MAXIMUM_ALLOWED_TTL = Duration.ofDays(1);

	SecurityStateProperties(@DefaultValue("15m") Duration maximumTtl, String keySecret,
			@DefaultValue("iam:security-state") String keyPrefix) {
		this.maximumTtl = requirePositiveMillis(maximumTtl, "Maximum security state TTL");
		if (this.maximumTtl.compareTo(MAXIMUM_ALLOWED_TTL) > 0) {
			throw new IllegalArgumentException("Maximum security state TTL must not exceed 24 hours");
		}
		this.keySecret = keySecret;
		this.keyPrefix = validateKeyPrefix(keyPrefix);
		decodedKeySecret().ifPresent(secret -> Arrays.fill(secret, (byte) 0));
	}

	Duration validateTtl(Duration value) {
		Duration validated = requirePositiveMillis(value, "Security state TTL");
		if (validated.compareTo(this.maximumTtl) > 0) {
			throw new IllegalArgumentException("Security state TTL must not exceed configured maximum TTL");
		}
		return validated;
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
			throw new IllegalArgumentException("Security state key secret must be valid Base64", exception);
		}
		if (decoded.length < MINIMUM_KEY_SECRET_BYTES) {
			throw new IllegalArgumentException("Security state key secret must contain at least 32 bytes");
		}
		return Optional.of(decoded);
	}

	boolean hasKeySecret() {
		return this.keySecret != null && !this.keySecret.isBlank();
	}

	@Override
	public String toString() {
		return "SecurityStateProperties[maximumTtl=" + this.maximumTtl
				+ ", keySecret=redacted, keyPrefix=" + this.keyPrefix + "]";
	}

	private static Duration requirePositiveMillis(Duration value, String name) {
		Objects.requireNonNull(value, name + " must not be null");
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
		Objects.requireNonNull(value, "Security state key prefix must not be null");
		if (value.isEmpty() || value.length() > 64
				|| !value.chars().allMatch(character -> character >= 'a' && character <= 'z'
						|| character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
						|| character == ':' || character == '_' || character == '-')) {
			throw new IllegalArgumentException(
					"Security state key prefix must contain 1 to 64 letters, digits, colons, underscores, or hyphens");
		}
		return value;
	}

}
