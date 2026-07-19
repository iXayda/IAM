package com.ixayda.iam.scim.internal;

import java.util.Set;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupMembership;

record ScimGroupView(Group group, Set<GroupMembership> members) {

	ScimGroupView {
		members = Set.copyOf(members);
	}

}
