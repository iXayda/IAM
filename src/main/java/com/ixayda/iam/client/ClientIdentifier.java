package com.ixayda.iam.client;

import java.util.Objects;
import java.util.regex.Pattern;

public record ClientIdentifier(String value) {

	private static final Pattern VALID_VALUE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._~-]{0,127}");

	public ClientIdentifier {
		Objects.requireNonNull(value, "Client identifier must not be null");
		if (!VALID_VALUE.matcher(value).matches()) {
			throw new IllegalArgumentException(
					"Client identifier must contain 1 to 128 URI-unreserved ASCII characters and start with a letter or digit");
		}
	}

	@Override
	public String toString() {
		return this.value;
	}

}
