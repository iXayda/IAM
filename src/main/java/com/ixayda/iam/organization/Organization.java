package com.ixayda.iam.organization;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

import com.ixayda.iam.tenant.TenantId;

public record Organization(OrganizationId id, TenantId tenantId, String slug, String displayName,
		OrganizationStatus status, long version, Instant createdAt, Instant updatedAt) {

	private static final int MAX_DISPLAY_NAME_LENGTH = 200;

	private static final Pattern VALID_SLUG = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

	public Organization {
		Objects.requireNonNull(id, "Organization ID must not be null");
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		slug = validateSlug(slug);
		displayName = normalizeDisplayName(displayName);
		Objects.requireNonNull(status, "Organization status must not be null");
		Objects.requireNonNull(createdAt, "Organization creation time must not be null");
		Objects.requireNonNull(updatedAt, "Organization update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("Organization version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Organization update time must not be before its creation time");
		}
	}

	public boolean isActive() {
		return this.status == OrganizationStatus.ACTIVE;
	}

	public Organization activate(Instant changedAt) {
		return changeStatus(OrganizationStatus.ACTIVE, changedAt);
	}

	public Organization disable(Instant changedAt) {
		return changeStatus(OrganizationStatus.DISABLED, changedAt);
	}

	static String normalizeDisplayName(String displayName) {
		Objects.requireNonNull(displayName, "Organization display name must not be null");
		String normalized = displayName.strip();
		if (normalized.isEmpty() || normalized.length() > MAX_DISPLAY_NAME_LENGTH) {
			throw new IllegalArgumentException("Organization display name must contain 1 to 200 characters");
		}
		return normalized;
	}

	static String validateSlug(String slug) {
		Objects.requireNonNull(slug, "Organization slug must not be null");
		if (!VALID_SLUG.matcher(slug).matches() || slug.endsWith("-")) {
			throw new IllegalArgumentException(
					"Organization slug must contain 1 to 63 lowercase letters, digits, or hyphens, and must start and end with a letter or digit");
		}
		return slug;
	}

	private Organization changeStatus(OrganizationStatus targetStatus, Instant changedAt) {
		Objects.requireNonNull(changedAt, "Organization status change time must not be null");
		if (this.status == targetStatus) {
			return this;
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("Organization status change time must not be before its last update");
		}
		return new Organization(this.id, this.tenantId, this.slug, this.displayName, targetStatus,
				Math.incrementExact(this.version), this.createdAt, changedAt);
	}

}
