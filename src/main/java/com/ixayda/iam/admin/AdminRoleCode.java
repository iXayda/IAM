package com.ixayda.iam.admin;

import java.util.Objects;
import java.util.regex.Pattern;

public record AdminRoleCode(String value) {

	private static final Pattern FORMAT = Pattern.compile("^[a-z][a-z0-9_]{2,79}$");

	public static final AdminRoleCode SUPER_ADMIN = new AdminRoleCode("super_admin");

	public static final AdminRoleCode ADMIN_MANAGER = new AdminRoleCode("admin_manager");

	public AdminRoleCode {
		Objects.requireNonNull(value, "Admin role code must not be null");
		if (!FORMAT.matcher(value).matches()) {
			throw new IllegalArgumentException("Admin role code must use canonical lowercase snake case");
		}
	}

	public static AdminRoleCode from(String value) {
		return new AdminRoleCode(value);
	}

	@Override
	public String toString() {
		return this.value;
	}

}
