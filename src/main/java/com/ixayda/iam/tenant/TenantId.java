package com.ixayda.iam.tenant;

import java.util.Objects;
import java.util.UUID;

public record TenantId(UUID value) {

	public static final TenantId DEFAULT =
			new TenantId(UUID.fromString("00000000-0000-0000-0000-000000000001"));

	public TenantId {
		Objects.requireNonNull(value, "Tenant ID must not be null");
	}

	public static TenantId random() {
		return new TenantId(UUID.randomUUID());
	}

	public static TenantId from(String value) {
		Objects.requireNonNull(value, "Tenant ID must not be null");
		return new TenantId(UUID.fromString(value));
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
