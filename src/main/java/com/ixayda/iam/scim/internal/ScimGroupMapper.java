package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.Comparator;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupMembership;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.types.Meta;
import org.springframework.stereotype.Component;

@Component
final class ScimGroupMapper {

	private static final Comparator<GroupMembership> MEMBER_ORDER =
			Comparator.comparing((membership) -> membership.userId().value());

	private final ScimProperties properties;

	ScimGroupMapper(ScimProperties properties) {
		this.properties = properties;
	}

	GroupResource map(ScimGroupView view, URI location, ScimGroupAttributeSelection selection) {
		Group group = view.group();
		if (group.isDeleted()) {
			throw new IllegalArgumentException("Deleted groups cannot be mapped to SCIM resources");
		}
		GroupResource resource = new GroupResource();
		resource.setId(group.id().toString());
		if (selection.includes("displayName")) {
			resource.setDisplayName(group.displayName());
		}
		boolean membersSelected = selection.includes("members", "value")
				|| selection.includes("members", "type") || selection.includes("members", "$ref");
		if (selection.includes("members") && membersSelected) {
			resource.setMembers(view.members().stream()
				.sorted(MEMBER_ORDER)
				.map((membership) -> member(membership, selection))
				.toList());
		}
		resource.setMeta(metadata(group, location, selection));
		return resource;
	}

	private Member member(GroupMembership membership, ScimGroupAttributeSelection selection) {
		Member member = new Member();
		if (selection.includes("members", "value")) {
			member.setValue(membership.userId().toString());
		}
		if (selection.includes("members", "type")) {
			member.setType("User");
		}
		if (selection.includes("members", "$ref")) {
			member.setRef(this.properties.endpoint(ScimUserController.USERS_PATH, membership.userId().toString()));
		}
		return member;
	}

	private static Meta metadata(Group group, URI location, ScimGroupAttributeSelection selection) {
		Meta metadata = new Meta();
		boolean present = false;
		if (selection.includes("meta", "resourceType")) {
			metadata.setResourceType("Group");
			present = true;
		}
		if (selection.includes("meta", "created")) {
			metadata.setCreatedMillis(group.createdAt().toEpochMilli());
			present = true;
		}
		if (selection.includes("meta", "lastModified")) {
			metadata.setLastModifiedMillis(group.updatedAt().toEpochMilli());
			present = true;
		}
		if (selection.includes("meta", "location")) {
			metadata.setLocation(location);
			present = true;
		}
		return present ? metadata : null;
	}

}
