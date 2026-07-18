package com.ixayda.iam.group;

import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface GroupOperations {

	Group create(TenantId tenantId, CreateGroupRequest request);

	Optional<Group> findById(TenantId tenantId, GroupId groupId);

	Group updateDisplayName(TenantId tenantId, GroupId groupId, long expectedVersion, String displayName);

	Group delete(TenantId tenantId, GroupId groupId, long expectedVersion);

	Set<GroupMembership> findMembers(TenantId tenantId, GroupId groupId);

	Group replaceMembers(TenantId tenantId, GroupId groupId, long expectedVersion, Set<UserId> memberIds);

}
