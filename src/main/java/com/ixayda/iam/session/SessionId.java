package com.ixayda.iam.session;

import java.util.Objects;
import java.util.UUID;

public record SessionId(UUID value) {

	public SessionId {
		Objects.requireNonNull(value, "Session ID must not be null");
	}

	public static SessionId random() {
		return new SessionId(UUID.randomUUID());
	}

	public static SessionId from(String value) {
		Objects.requireNonNull(value, "Session ID must not be null");
		return new SessionId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
