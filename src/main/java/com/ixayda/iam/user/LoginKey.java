package com.ixayda.iam.user;

import java.util.Locale;
import java.util.Objects;

public final class LoginKey {

	private final String canonicalValue;

	private LoginKey(String canonicalValue) {
		this.canonicalValue = validateCanonicalValue(canonicalValue);
	}

	public static LoginKey from(String value) {
		return canonical(LoginIdentifier.canonicalizeLoginKey(value));
	}

	static LoginKey canonical(String canonicalValue) {
		return new LoginKey(canonicalValue);
	}

	public String canonicalValue() {
		return this.canonicalValue;
	}

	@Override
	public boolean equals(Object candidate) {
		return this == candidate || candidate instanceof LoginKey other
				&& this.canonicalValue.equals(other.canonicalValue);
	}

	@Override
	public int hashCode() {
		return this.canonicalValue.hashCode();
	}

	@Override
	public String toString() {
		return "LoginKey[redacted]";
	}

	private static String validateCanonicalValue(String canonicalValue) {
		Objects.requireNonNull(canonicalValue, "Canonical login key must not be null");
		if (canonicalValue.length() < 3 || canonicalValue.length() > 254
				|| !canonicalValue.equals(canonicalValue.strip())
				|| !canonicalValue.equals(canonicalValue.toLowerCase(Locale.ROOT))
				|| !canonicalValue.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
			throw new IllegalArgumentException("Canonical login key is invalid");
		}
		return canonicalValue;
	}

}
