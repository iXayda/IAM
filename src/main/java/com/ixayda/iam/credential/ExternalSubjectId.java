package com.ixayda.iam.credential;

import java.util.Objects;

public record ExternalSubjectId(String value) {

	public static final int MAX_LENGTH = 512;

	public ExternalSubjectId {
		Objects.requireNonNull(value, "External subject ID must not be null");
		if (value.isBlank() || value.length() > MAX_LENGTH || !value.equals(value.strip())
				|| value.codePoints().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException(
					"External subject ID must contain 1 to 512 non-control characters without surrounding whitespace");
		}
	}

	public static ExternalSubjectId from(String value) {
		return new ExternalSubjectId(value);
	}

	@Override
	public String toString() {
		return "ExternalSubjectId[redacted]";
	}

}
