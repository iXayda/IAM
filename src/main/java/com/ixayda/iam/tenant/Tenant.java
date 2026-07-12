package com.ixayda.iam.tenant;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

public record Tenant(TenantId id, String slug, String displayName, TenantStatus status, long version,
		Instant createdAt, Instant updatedAt) {

	private static final int MAX_DISPLAY_NAME_LENGTH = 200;

	private static final Pattern VALID_SLUG = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

	public Tenant {
		Objects.requireNonNull(id, "Tenant ID must not be null");
		slug = validateSlug(slug);
		displayName = normalizeDisplayName(displayName);
		Objects.requireNonNull(status, "Tenant status must not be null");
		Objects.requireNonNull(createdAt, "Tenant creation time must not be null");
		Objects.requireNonNull(updatedAt, "Tenant update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("Tenant version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Tenant update time must not be before its creation time");
		}

		boolean defaultId = TenantId.DEFAULT.equals(id);
		boolean defaultSlug = "default".equals(slug);
		if (defaultId != defaultSlug || (defaultId && status != TenantStatus.ACTIVE)) {
			throw new IllegalArgumentException("The built-in default tenant must keep its ID, slug, and active status");
		}
	}

	public boolean isActive() {
		return this.status == TenantStatus.ACTIVE;
	}

	public boolean isBuiltInDefault() {
		return TenantId.DEFAULT.equals(this.id);
	}

	public Tenant activate(Instant changedAt) {
		return changeStatus(TenantStatus.ACTIVE, changedAt);
	}

	public Tenant disable(Instant changedAt) {
		if (isBuiltInDefault()) {
			throw new IllegalStateException("The built-in default tenant cannot be disabled");
		}
		return changeStatus(TenantStatus.DISABLED, changedAt);
	}

	static String normalizeDisplayName(String displayName) {
		Objects.requireNonNull(displayName, "Tenant display name must not be null");
		String normalized = displayName.strip();
		if (normalized.isEmpty() || normalized.length() > MAX_DISPLAY_NAME_LENGTH) {
			throw new IllegalArgumentException("Tenant display name must contain 1 to 200 characters");
		}
		return normalized;
	}

	static String validateSlug(String slug) {
		Objects.requireNonNull(slug, "Tenant slug must not be null");
		if (!VALID_SLUG.matcher(slug).matches() || slug.endsWith("-")) {
			throw new IllegalArgumentException(
					"Tenant slug must contain 1 to 63 lowercase letters, digits, or hyphens, and must start and end with a letter or digit");
		}
		return slug;
	}

	private Tenant changeStatus(TenantStatus targetStatus, Instant changedAt) {
		Objects.requireNonNull(changedAt, "Tenant status change time must not be null");
		if (this.status == targetStatus) {
			return this;
		}
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("Tenant status change time must not be before its last update");
		}
		return new Tenant(this.id, this.slug, this.displayName, targetStatus, Math.incrementExact(this.version),
				this.createdAt, changedAt);
	}

}
