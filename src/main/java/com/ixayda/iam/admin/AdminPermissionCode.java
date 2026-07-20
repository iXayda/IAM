package com.ixayda.iam.admin;

import java.util.Objects;
import java.util.regex.Pattern;

public record AdminPermissionCode(String value) {

	private static final Pattern FORMAT =
			Pattern.compile("^[a-z][a-z0-9_]*(?:[.][a-z][a-z0-9_]*)+$");

	public static final AdminPermissionCode ASSIGN_ROLES = new AdminPermissionCode("admin.role.assign");

	public static final AdminPermissionCode READ_ROLES = new AdminPermissionCode("role.read");

	public static final AdminPermissionCode READ_AUDIT = new AdminPermissionCode("audit.read");

	public AdminPermissionCode {
		Objects.requireNonNull(value, "Admin permission code must not be null");
		if (value.length() > 100 || !FORMAT.matcher(value).matches()) {
			throw new IllegalArgumentException("Admin permission code must use canonical lowercase segments");
		}
	}

	public static AdminPermissionCode from(String value) {
		return new AdminPermissionCode(value);
	}

	@Override
	public String toString() {
		return this.value;
	}

}
