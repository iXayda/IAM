package com.ixayda.iam.user;

import java.util.Objects;

public record ExternalSubjectId(String value) {

	public static final int MAX_LENGTH = 512;

	public ExternalSubjectId {
		Objects.requireNonNull(value, "External subject ID must not be null");
		if (value.isEmpty() || value.length() > MAX_LENGTH
				|| !value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
			throw new IllegalArgumentException(
					"External subject ID must contain 1 to 512 visible ASCII characters");
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
