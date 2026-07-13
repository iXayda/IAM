package com.ixayda.iam.credential;

import java.util.Objects;
import java.util.regex.Pattern;

public record ExternalCredentialProviderId(String value) {

	public static final int MAX_LENGTH = 64;

	private static final Pattern VALUE = Pattern.compile("[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?");

	public ExternalCredentialProviderId {
		Objects.requireNonNull(value, "External credential provider ID must not be null");
		if (value.length() > MAX_LENGTH || !VALUE.matcher(value).matches()) {
			throw new IllegalArgumentException(
					"External credential provider ID must be a 1 to 64 character lowercase kebab-case value");
		}
	}

	public static ExternalCredentialProviderId from(String value) {
		return new ExternalCredentialProviderId(value);
	}

	@Override
	public String toString() {
		return this.value;
	}

}
