package com.ixayda.iam.group;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record GroupMembership(TenantId tenantId, GroupId groupId, UserId userId, Instant createdAt) {

	public GroupMembership {
		Objects.requireNonNull(tenantId, "Membership tenant ID must not be null");
		Objects.requireNonNull(groupId, "Membership group ID must not be null");
		Objects.requireNonNull(userId, "Membership user ID must not be null");
		Objects.requireNonNull(createdAt, "Membership creation time must not be null");
	}

}
