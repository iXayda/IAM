package com.ixayda.iam.group;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

public final class GroupNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	private final GroupId groupId;

	public GroupNotFoundException(TenantId tenantId, GroupId groupId) {
		super("Group not found: " + groupId);
		this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		this.groupId = Objects.requireNonNull(groupId, "Group ID must not be null");
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public GroupId groupId() {
		return this.groupId;
	}

}
