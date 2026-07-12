package com.ixayda.iam.user;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

public record LoginIdentifier(LoginIdentifierType type, String value, String canonicalValue) {

	private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9._:-]{3,80}");

	private static final Pattern EMAIL = Pattern.compile("[\\x21-\\x3F\\x41-\\x7E]+@[\\x21-\\x3F\\x41-\\x7E]+");

	private static final Pattern PHONE_INPUT = Pattern.compile("\\+?[0-9(). -]+");

	private static final Pattern PHONE_CANONICAL = Pattern.compile("[1-9][0-9]{5,14}");

	private static final Pattern NON_DIGIT = Pattern.compile("[^0-9]");

	public LoginIdentifier {
		Objects.requireNonNull(type, "Login identifier type must not be null");
		value = normalizeValue(value);
		String expectedCanonical = canonicalize(type, value);
		Objects.requireNonNull(canonicalValue, "Canonical login identifier must not be null");
		if (!expectedCanonical.equals(canonicalValue)) {
			throw new IllegalArgumentException("Canonical login identifier does not match its value");
		}
	}

	public static LoginIdentifier username(String value) {
		return create(LoginIdentifierType.USERNAME, value);
	}

	/**
	 * Creates an email identifier using the initial ASCII policy, which treats the
	 * complete address, including its local part, as case-insensitive.
	 */
	public static LoginIdentifier email(String value) {
		return create(LoginIdentifierType.EMAIL, value);
	}

	public static LoginIdentifier phone(String value) {
		return create(LoginIdentifierType.PHONE, value);
	}

	public LoginKey loginKey() {
		return LoginKey.canonical(this.canonicalValue);
	}

	static List<LoginIdentifier> validatedCopy(List<LoginIdentifier> identifiers) {
		Objects.requireNonNull(identifiers, "Login identifiers must not be null");
		List<LoginIdentifier> copy = List.copyOf(identifiers);
		if (copy.isEmpty()) {
			throw new IllegalArgumentException("At least one login identifier is required");
		}

		Set<LoginIdentifierType> types = EnumSet.noneOf(LoginIdentifierType.class);
		Set<String> canonicalValues = new HashSet<>();
		for (LoginIdentifier identifier : copy) {
			if (!types.add(identifier.type())) {
				throw new IllegalArgumentException("Only one login identifier of each type is allowed");
			}
			if (!canonicalValues.add(identifier.canonicalValue())) {
				throw new IllegalArgumentException("Login identifiers must be unambiguous");
			}
		}
		return copy;
	}

	@Override
	public String toString() {
		return "LoginIdentifier[type=" + this.type + "]";
	}

	private static LoginIdentifier create(LoginIdentifierType type, String value) {
		String normalizedValue = normalizeValue(value);
		return new LoginIdentifier(type, normalizedValue, canonicalize(type, normalizedValue));
	}

	private static String normalizeValue(String value) {
		Objects.requireNonNull(value, "Login identifier value must not be null");
		String normalized = value.strip();
		if (normalized.isEmpty()) {
			throw new IllegalArgumentException("Login identifier value must not be empty");
		}
		return normalized;
	}

	static String canonicalizeLoginKey(String value) {
		String normalizedValue = normalizeValue(value);
		if (normalizedValue.indexOf('@') >= 0) {
			return canonicalizeEmail(normalizedValue);
		}
		String canonicalPhone = canonicalPhoneIfValid(normalizedValue);
		return canonicalPhone != null ? canonicalPhone : canonicalizeUsername(normalizedValue);
	}

	private static String canonicalize(LoginIdentifierType type, String value) {
		return switch (type) {
			case USERNAME -> canonicalizeUsername(value);
			case EMAIL -> canonicalizeEmail(value);
			case PHONE -> canonicalizePhone(value);
		};
	}

	private static String canonicalizeUsername(String value) {
		if (!USERNAME.matcher(value).matches()) {
			throw new IllegalArgumentException(
					"Username must contain 3 to 80 ASCII letters, digits, dots, underscores, colons, or hyphens");
		}
		String canonical = value.toLowerCase(Locale.ROOT);
		String canonicalPhone = canonicalPhoneIfValid(value);
		if (canonicalPhone != null && !canonicalPhone.equals(canonical)) {
			throw new IllegalArgumentException("Username must not be ambiguous with a formatted phone number");
		}
		return canonical;
	}

	private static String canonicalizeEmail(String value) {
		if (value.length() > 254 || !EMAIL.matcher(value).matches()) {
			throw new IllegalArgumentException(
					"Email must contain one @ separator and 3 to 254 printable ASCII characters without spaces");
		}
		return value.toLowerCase(Locale.ROOT);
	}

	private static String canonicalizePhone(String value) {
		String canonical = canonicalPhoneIfValid(value);
		if (canonical == null) {
			throw new IllegalArgumentException("Phone must contain a 6 to 15 digit canonical number");
		}
		return canonical;
	}

	private static String canonicalPhoneIfValid(String value) {
		if (value.length() > 32 || !PHONE_INPUT.matcher(value).matches()) {
			return null;
		}
		String canonical = NON_DIGIT.matcher(value).replaceAll("");
		return PHONE_CANONICAL.matcher(canonical).matches() ? canonical : null;
	}

}
