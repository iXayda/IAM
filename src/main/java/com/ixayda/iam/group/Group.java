package com.ixayda.iam.group;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public record Group(GroupId id, TenantId tenantId, String displayName, GroupStatus status, long version,
		Instant createdAt, Instant updatedAt) {

	private static final int MAXIMUM_DISPLAY_NAME_LENGTH = 200;

	public Group {
		Objects.requireNonNull(id, "Group ID must not be null");
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		displayName = normalizeDisplayName(displayName);
		Objects.requireNonNull(status, "Group status must not be null");
		Objects.requireNonNull(createdAt, "Group creation time must not be null");
		Objects.requireNonNull(updatedAt, "Group update time must not be null");
		if (version < 0) {
			throw new IllegalArgumentException("Group version must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("Group update time must not be before its creation time");
		}
	}

	public boolean isActive() {
		return this.status == GroupStatus.ACTIVE;
	}

	public boolean isDeleted() {
		return this.status == GroupStatus.DELETED;
	}

	public Group updateDisplayName(String replacement, Instant changedAt) {
		String normalized = normalizeDisplayName(replacement);
		Objects.requireNonNull(changedAt, "Group display name change time must not be null");
		if (this.displayName.equals(normalized)) {
			return this;
		}
		if (isDeleted()) {
			throw new IllegalStateException("Deleted group display name cannot be changed");
		}
		validateChangeTime(changedAt);
		return new Group(this.id, this.tenantId, normalized, this.status, Math.incrementExact(this.version),
				this.createdAt, changedAt);
	}

	public Group delete(Instant changedAt) {
		Objects.requireNonNull(changedAt, "Group deletion time must not be null");
		if (isDeleted()) {
			return this;
		}
		validateChangeTime(changedAt);
		return new Group(this.id, this.tenantId, this.displayName, GroupStatus.DELETED,
				Math.incrementExact(this.version), this.createdAt, changedAt);
	}

	@Override
	public String toString() {
		return "Group[id=" + this.id + ", tenantId=" + this.tenantId + ", status=" + this.status + ", version="
				+ this.version + ", createdAt=" + this.createdAt + ", updatedAt=" + this.updatedAt + "]";
	}

	static String normalizeDisplayName(String value) {
		Objects.requireNonNull(value, "Group display name must not be null");
		if (value.codePoints().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException(
					"Group display name must contain 1 to 200 characters without control characters");
		}
		String normalized = value.strip();
		int length = normalized.codePointCount(0, normalized.length());
		if (length == 0 || length > MAXIMUM_DISPLAY_NAME_LENGTH) {
			throw new IllegalArgumentException(
					"Group display name must contain 1 to 200 characters without control characters");
		}
		return normalized;
	}

	private void validateChangeTime(Instant changedAt) {
		if (changedAt.isBefore(this.updatedAt)) {
			throw new IllegalArgumentException("Group change time must not be before its last update");
		}
	}

}
