package com.ixayda.iam.group;

import java.util.Objects;
import java.util.UUID;

public record GroupId(UUID value) {

	public GroupId {
		Objects.requireNonNull(value, "Group ID must not be null");
	}

	public static GroupId random() {
		return new GroupId(UUID.randomUUID());
	}

	public static GroupId from(String value) {
		Objects.requireNonNull(value, "Group ID must not be null");
		return new GroupId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
