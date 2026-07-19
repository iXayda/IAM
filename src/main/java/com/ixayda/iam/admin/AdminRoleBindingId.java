package com.ixayda.iam.admin;

import java.util.Objects;
import java.util.UUID;

public record AdminRoleBindingId(UUID value) {

	public AdminRoleBindingId {
		Objects.requireNonNull(value, "Admin role binding ID must not be null");
	}

	public static AdminRoleBindingId random() {
		return new AdminRoleBindingId(UUID.randomUUID());
	}

	@Override
	public String toString() {
		return this.value.toString();
	}

}
