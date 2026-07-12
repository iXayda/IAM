package com.ixayda.iam.credential;

import java.util.Objects;

public final class PasswordAttempt {

	public static final int MAX_LENGTH = 256;

	private final char[] value;

	public PasswordAttempt(char[] value) {
		Objects.requireNonNull(value, "Password attempt must not be null");
		if (value.length == 0 || value.length > MAX_LENGTH) {
			throw new IllegalArgumentException("Password attempt must contain 1 to 256 characters");
		}
		this.value = value.clone();
	}

	/**
	 * Returns a caller-owned copy that should be cleared immediately after use.
	 */
	public char[] copy() {
		return this.value.clone();
	}

	public int length() {
		return this.value.length;
	}

	@Override
	public String toString() {
		return "PasswordAttempt[redacted]";
	}

}
