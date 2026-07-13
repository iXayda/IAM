package com.ixayda.iam.user;

import java.util.Objects;
import java.util.regex.Pattern;

public record ExternalIdentityProviderId(String value) {

	public static final int MAX_LENGTH = 64;

	private static final Pattern VALUE = Pattern.compile("[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?");

	public ExternalIdentityProviderId {
		Objects.requireNonNull(value, "External identity provider ID must not be null");
		if (value.length() > MAX_LENGTH || !VALUE.matcher(value).matches()) {
			throw new IllegalArgumentException(
					"External identity provider ID must be a 1 to 64 character lowercase kebab-case value");
		}
	}

	public static ExternalIdentityProviderId from(String value) {
		return new ExternalIdentityProviderId(value);
	}

	@Override
	public String toString() {
		return this.value;
	}

}
