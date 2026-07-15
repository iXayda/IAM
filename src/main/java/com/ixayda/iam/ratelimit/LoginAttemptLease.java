package com.ixayda.iam.ratelimit;

import java.util.Objects;

/**
 * Opaque acknowledgement lease for one allowed login attempt. It does not
 * authorize authentication and must not be logged or exposed to clients.
 */
public record LoginAttemptLease(String value) {

	public LoginAttemptLease {
		Objects.requireNonNull(value, "Login attempt lease must not be null");
		if (value.length() < 22 || value.length() > 64
				|| !value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
			throw new IllegalArgumentException(
					"Login attempt lease must contain 22 to 64 visible ASCII characters");
		}
	}

	public static LoginAttemptLease from(String value) {
		return new LoginAttemptLease(value);
	}

	@Override
	public String toString() {
		return "LoginAttemptLease[redacted]";
	}

}
