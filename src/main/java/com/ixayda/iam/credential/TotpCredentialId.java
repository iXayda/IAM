package com.ixayda.iam.credential;

import java.util.Objects;
import java.util.UUID;

public record TotpCredentialId(UUID value) {

	public TotpCredentialId {
		Objects.requireNonNull(value, "TOTP credential ID must not be null");
	}

	public static TotpCredentialId random() {
		return new TotpCredentialId(UUID.randomUUID());
	}

	public static TotpCredentialId from(String value) {
		return new TotpCredentialId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
