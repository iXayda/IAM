package com.ixayda.iam.admin;

import java.time.Instant;
import java.util.Objects;

public record AdminRole(AdminRoleCode code, String name, String description, AdminRoleStatus status,
		boolean protectedRole, long version, Instant createdAt, Instant updatedAt) {

	public AdminRole {
		Objects.requireNonNull(code, "Admin role code must not be null");
		name = requireText(name, 120, "Admin role name");
		description = requireText(description, 500, "Admin role description");
		Objects.requireNonNull(status, "Admin role status must not be null");
		Objects.requireNonNull(createdAt, "Admin role creation time must not be null");
		Objects.requireNonNull(updatedAt, "Admin role update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("Admin role version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Admin role update time must not be before its creation time");
		}
	}

	public boolean isActive() {
		return this.status == AdminRoleStatus.ACTIVE;
	}

	private static String requireText(String value, int maximumLength, String field) {
		Objects.requireNonNull(value, field + " must not be null");
		if (!value.equals(value.strip()) || value.isEmpty() || value.length() > maximumLength
				|| value.chars().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException(field + " is invalid");
		}
		return value;
	}

}
