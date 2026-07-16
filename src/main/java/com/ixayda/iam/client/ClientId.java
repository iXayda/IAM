package com.ixayda.iam.client;

import java.util.Objects;
import java.util.UUID;

public record ClientId(UUID value) {

	public ClientId {
		Objects.requireNonNull(value, "Client ID must not be null");
	}

	public static ClientId random() {
		return new ClientId(UUID.randomUUID());
	}

	public static ClientId from(String value) {
		Objects.requireNonNull(value, "Client ID must not be null");
		return new ClientId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
