package com.ixayda.iam.scim.internal;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupDirectoryQuery;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
import com.ixayda.iam.group.GroupMembershipLimitExceededException;
import com.ixayda.iam.group.GroupNotFoundException;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.group.GroupPage;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.UserNotFoundException;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class ScimGroupService {

	private static final String NOT_FOUND_DETAIL = "The requested SCIM group was not found.";

	private final TenantOperations tenants;

	private final GroupOperations groups;

	ScimGroupService(TenantOperations tenants, GroupOperations groups) {
		this.tenants = tenants;
		this.groups = groups;
	}

	ScimGroupView find(TenantId tenantId, String groupId) throws ResourceNotFoundException, BadRequestException {
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
		catch (GroupMembershipLimitExceededException exception) {
			throw tooMany();
		}
	}

	ScimGroupPage findPage(TenantId tenantId, GroupDirectoryQuery query, boolean includeMembers)
			throws ResourceNotFoundException, BadRequestException {
		try {
			this.tenants.requireActive(tenantId);
		}
		catch (TenantDisabledException | TenantNotFoundException exception) {
			throw notFound();
		}
		GroupPage page = this.groups.findDirectoryPage(tenantId, query);
		if (page.totalResults() > Integer.MAX_VALUE) {
			throw BadRequestException.tooMany("The SCIM Group query matched too many resources.");
		}
		Set<GroupId> groupIds = page.groups()
			.stream()
			.map(Group::id)
			.collect(Collectors.toCollection(LinkedHashSet::new));
		Map<GroupId, Set<GroupMembership>> memberships;
		try {
			memberships = includeMembers ? this.groups.findMembers(tenantId, groupIds) : Map.of();
		}
		catch (GroupMembershipLimitExceededException exception) {
			throw tooMany();
		}
		return new ScimGroupPage(page.totalResults(), page.groups().stream()
			.map(group -> new ScimGroupView(group, memberships.getOrDefault(group.id(), Set.of())))
			.toList());
	}

	@Transactional(rollbackFor = com.unboundid.scim2.common.exceptions.ScimException.class)
	public ScimGroupView create(TenantId tenantId, ScimGroupCreateRequest command)
			throws ResourceNotFoundException, BadRequestException {
		try {
			Group created = this.groups.create(tenantId, command.request(), command.memberIds());
			return new ScimGroupView(created, this.groups.findMembers(tenantId, created.id()));
		}
		catch (TenantDisabledException | TenantNotFoundException exception) {
			throw notFound();
		}
		catch (UserNotFoundException | GroupMembershipLimitExceededException exception) {
			throw invalidMembers();
		}
	}

	private static ResourceNotFoundException notFound() {
		return new ResourceNotFoundException(NOT_FOUND_DETAIL);
	}

	private static BadRequestException tooMany() {
		return BadRequestException.tooMany("The requested SCIM Group membership set is too large.");
	}

	private static BadRequestException invalidMembers() {
		return BadRequestException.invalidValue("The SCIM Group members contain an invalid or unavailable User.");
	}

}
