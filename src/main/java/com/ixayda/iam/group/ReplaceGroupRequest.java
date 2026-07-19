package com.ixayda.iam.group;

import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.user.UserId;

public record ReplaceGroupRequest(String displayName, Set<UserId> memberIds) {

	public ReplaceGroupRequest {
		displayName = Group.normalizeDisplayName(displayName);
		memberIds = Set.copyOf(Objects.requireNonNull(memberIds, "Group member IDs must not be null"));
	}

	@Override
	public String toString() {
		return "ReplaceGroupRequest[displayNamePresent=true, memberCount=" + this.memberIds.size() + "]";
	}

}
