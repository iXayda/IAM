package com.ixayda.iam.scim.internal;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupNotFoundException;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;

@Service
class ScimGroupService {

	private static final String NOT_FOUND_DETAIL = "The requested SCIM group was not found.";

	private final TenantOperations tenants;

	private final GroupOperations groups;

	ScimGroupService(TenantOperations tenants, GroupOperations groups) {
		this.tenants = tenants;
		this.groups = groups;
	}

	ScimGroupView find(TenantId tenantId, String groupId) throws ResourceNotFoundException {
		GroupId parsedId;
		try {
			parsedId = GroupId.from(groupId);
			if (!parsedId.toString().equals(groupId)) {
				throw new IllegalArgumentException("SCIM group ID must use its canonical representation");
			}
			this.tenants.requireActive(tenantId);
		}
		catch (IllegalArgumentException | TenantDisabledException | TenantNotFoundException exception) {
			throw notFound();
		}
		Group group = this.groups.findById(tenantId, parsedId).orElseThrow(ScimGroupService::notFound);
		try {
			return new ScimGroupView(group, this.groups.findMembers(tenantId, parsedId));
		}
		catch (GroupNotFoundException exception) {
			throw notFound();
		}
	}

	private static ResourceNotFoundException notFound() {
		return new ResourceNotFoundException(NOT_FOUND_DETAIL);
	}

}
