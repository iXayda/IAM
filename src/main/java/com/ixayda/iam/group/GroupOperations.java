package com.ixayda.iam.group;

import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;

public interface GroupOperations {

	Group create(TenantId tenantId, CreateGroupRequest request);

	Optional<Group> findById(TenantId tenantId, GroupId groupId);

	Group updateDisplayName(TenantId tenantId, GroupId groupId, long expectedVersion, String displayName);

	Group delete(TenantId tenantId, GroupId groupId, long expectedVersion);

}
