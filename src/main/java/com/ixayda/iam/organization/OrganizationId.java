package com.ixayda.iam.organization;

import java.util.Objects;
import java.util.UUID;

public record OrganizationId(UUID value) {

	public OrganizationId {
		Objects.requireNonNull(value, "Organization ID must not be null");
	}

	public static OrganizationId random() {
		return new OrganizationId(UUID.randomUUID());
	}

	public static OrganizationId from(String value) {
		Objects.requireNonNull(value, "Organization ID must not be null");
		return new OrganizationId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
