package com.ixayda.iam.credential;

import java.util.Objects;

public final class NewPassword {

	public static final int MIN_LENGTH = 8;

	public static final int MAX_LENGTH = 256;

	private final char[] value;

	public NewPassword(char[] value) {
		Objects.requireNonNull(value, "New password must not be null");
		if (value.length < MIN_LENGTH || value.length > MAX_LENGTH || isBlank(value)) {
			throw new IllegalArgumentException("New password must contain 8 to 256 characters and not be blank");
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
		return "NewPassword[redacted]";
	}

	private static boolean isBlank(char[] value) {
		for (char character : value) {
			if (!Character.isWhitespace(character)) {
				return false;
			}
		}
		return true;
	}

}
