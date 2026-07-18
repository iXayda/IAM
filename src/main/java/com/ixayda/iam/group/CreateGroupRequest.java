package com.ixayda.iam.group;

public record CreateGroupRequest(String displayName) {

	public CreateGroupRequest {
		displayName = Group.normalizeDisplayName(displayName);
	}

	@Override
	public String toString() {
		return "CreateGroupRequest[displayNamePresent=true]";
	}

}
