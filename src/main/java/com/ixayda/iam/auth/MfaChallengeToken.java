package com.ixayda.iam.auth;

import java.util.Objects;

/**
 * Opaque 256-bit bearer secret for one MFA login challenge.
 */
public record MfaChallengeToken(String value) {

	public static final int ENCODED_LENGTH = 43;

	public MfaChallengeToken {
		Objects.requireNonNull(value, "MFA challenge token must not be null");
		if (value.length() != ENCODED_LENGTH || !value.chars().allMatch(MfaChallengeToken::isBase64UrlCharacter)) {
			throw new IllegalArgumentException(
					"MFA challenge token must be a 43-character unpadded Base64url value");
		}
	}

	public static MfaChallengeToken from(String value) {
		return new MfaChallengeToken(value);
	}

	@Override
	public String toString() {
		return "MfaChallengeToken[redacted]";
	}

	private static boolean isBase64UrlCharacter(int character) {
		return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
				|| character >= '0' && character <= '9' || character == '-' || character == '_';
	}

}
