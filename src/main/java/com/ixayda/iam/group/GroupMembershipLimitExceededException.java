package com.ixayda.iam.group;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class GroupMembershipLimitExceededException extends RuntimeException {

	private final TenantId tenantId;

	private final GroupId groupId;

	private final int maximumMembers;

	public GroupMembershipLimitExceededException(TenantId tenantId, GroupId groupId, int maximumMembers) {
		super("Group membership limit exceeded");
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.groupId = Objects.requireNonNull(groupId, "Group ID must not be null");
		if (maximumMembers < 1) {
			throw new IllegalArgumentException("Maximum group members must be positive");
		}
		this.maximumMembers = maximumMembers;
	}

	public TenantId getTenantId() {
		return this.tenantId;
	}

	public GroupId getGroupId() {
		return this.groupId;
	}

	public int getMaximumMembers() {
		return this.maximumMembers;
	}

}
