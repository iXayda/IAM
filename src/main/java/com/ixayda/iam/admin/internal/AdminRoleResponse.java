package com.ixayda.iam.admin.internal;

import java.util.Locale;
import java.util.Objects;

import com.ixayda.iam.admin.AdminRole;

record AdminRoleResponse(String code, String name, String description, String status, boolean protectedRole) {

	AdminRoleResponse {
		Objects.requireNonNull(code, "Admin role code must not be null");
		Objects.requireNonNull(name, "Admin role name must not be null");
		Objects.requireNonNull(description, "Admin role description must not be null");
		Objects.requireNonNull(status, "Admin role status must not be null");
	}

	static AdminRoleResponse from(AdminRole role) {
		Objects.requireNonNull(role, "Admin role must not be null");
		return new AdminRoleResponse(role.code().value(), role.name(), role.description(),
				role.status().name().toLowerCase(Locale.ROOT), role.protectedRole());
	}

}
