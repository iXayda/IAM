package com.ixayda.iam.user;

import java.util.Objects;
import java.util.UUID;

public record UserId(UUID value) {

	public UserId {
		Objects.requireNonNull(value, "User ID must not be null");
	}

	public static UserId random() {
		return new UserId(UUID.randomUUID());
	}

	public static UserId from(String value) {
		Objects.requireNonNull(value, "User ID must not be null");
		return new UserId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
