package com.ixayda.iam.securitystate;

import java.util.Objects;

/**
 * Opaque 256-bit, URL-safe token. It is a bearer secret and must not be logged.
 */
public record SecurityStateToken(String value) {

	public static final int ENCODED_LENGTH = 43;

	public SecurityStateToken {
		Objects.requireNonNull(value, "Security state token must not be null");
		if (value.length() != ENCODED_LENGTH || !value.chars().allMatch(SecurityStateToken::isBase64UrlCharacter)) {
			throw new IllegalArgumentException("Security state token must be a 43-character unpadded Base64url value");
		}
	}

	public static SecurityStateToken from(String value) {
		return new SecurityStateToken(value);
	}

	@Override
	public String toString() {
		return "SecurityStateToken[redacted]";
	}

	private static boolean isBase64UrlCharacter(int character) {
		return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
				|| character >= '0' && character <= '9' || character == '-' || character == '_';
	}

}
