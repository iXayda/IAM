package com.ixayda.iam.ratelimit;

import java.util.Objects;

/**
 * Opaque source identifier produced by a trusted ingress after proxy-chain
 * validation and canonicalization. Client-provided forwarding headers must not be
 * passed through directly.
 */
public record LoginAttemptSource(String value) {

	public static final int MAX_LENGTH = 512;

	public LoginAttemptSource {
		Objects.requireNonNull(value, "Login attempt source must not be null");
		if (value.isEmpty() || value.length() > MAX_LENGTH
				|| !value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
			throw new IllegalArgumentException(
					"Login attempt source must contain 1 to 512 visible ASCII characters");
		}
	}

	public static LoginAttemptSource trusted(String value) {
		return new LoginAttemptSource(value);
	}

	@Override
	public String toString() {
		return "LoginAttemptSource[redacted]";
	}

}
