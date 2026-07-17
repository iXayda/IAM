package com.ixayda.iam.user;

public record UserProfile(String displayName, String formattedName, String givenName, String familyName) {

	private static final int MAXIMUM_VALUE_LENGTH = 200;

	private static final UserProfile EMPTY = new UserProfile(null, null, null, null);

	public UserProfile {
		displayName = normalize(displayName, "User display name");
		formattedName = normalize(formattedName, "User formatted name");
		givenName = normalize(givenName, "User given name");
		familyName = normalize(familyName, "User family name");
	}

	public static UserProfile empty() {
		return EMPTY;
	}

	public boolean isEmpty() {
		return this.displayName == null && this.formattedName == null && this.givenName == null
				&& this.familyName == null;
	}

	@Override
	public String toString() {
		return "UserProfile[displayNamePresent=" + (this.displayName != null) + ", formattedNamePresent="
				+ (this.formattedName != null) + ", givenNamePresent=" + (this.givenName != null)
				+ ", familyNamePresent=" + (this.familyName != null) + "]";
	}

	private static String normalize(String value, String name) {
		if (value == null) {
			return null;
		}
		if (value.codePoints().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException(name + " must contain at most 200 characters without control characters");
		}
		String normalized = value.strip();
		if (normalized.isEmpty()) {
			return null;
		}
		if (normalized.codePointCount(0, normalized.length()) > MAXIMUM_VALUE_LENGTH) {
			throw new IllegalArgumentException(name + " must contain at most 200 characters without control characters");
		}
		return normalized;
	}

}
