package com.ixayda.iam.group;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class GroupConcurrentUpdateException extends RuntimeException {

	private final TenantId tenantId;

	private final GroupId groupId;

	private final long expectedVersion;

	public GroupConcurrentUpdateException(TenantId tenantId, GroupId groupId, long expectedVersion) {
		super("Group was updated concurrently: " + groupId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.groupId = Objects.requireNonNull(groupId, "Group ID must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected group version must not be negative");
		}
		this.expectedVersion = expectedVersion;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public GroupId groupId() {
		return this.groupId;
	}

	public long expectedVersion() {
		return this.expectedVersion;
	}

}
