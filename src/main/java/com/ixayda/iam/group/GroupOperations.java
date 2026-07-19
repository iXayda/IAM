package com.ixayda.iam.group;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public interface GroupOperations {

	int MAX_MEMBERS_PER_GROUP = 1_000;

	Group create(TenantId tenantId, CreateGroupRequest request);

	Optional<Group> findById(TenantId tenantId, GroupId groupId);

	GroupPage findDirectoryPage(TenantId tenantId, GroupDirectoryQuery query);

	Group updateDisplayName(TenantId tenantId, GroupId groupId, long expectedVersion, String displayName);

	Group delete(TenantId tenantId, GroupId groupId, long expectedVersion);

	Set<GroupMembership> findMembers(TenantId tenantId, GroupId groupId);

	Map<GroupId, Set<GroupMembership>> findMembers(TenantId tenantId, Set<GroupId> groupIds);

	Group replaceMembers(TenantId tenantId, GroupId groupId, long expectedVersion, Set<UserId> memberIds);

}
