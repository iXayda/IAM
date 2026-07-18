package com.ixayda.iam.group.internal;

import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupConcurrentUpdateException;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
import com.ixayda.iam.group.GroupNotFoundException;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultGroupOperations implements GroupOperations {

	private static final Comparator<UserId> USER_ID_ORDER = Comparator.comparing(UserId::value);

	private final JdbcGroupRepository repository;

	private final TenantOperations tenants;

	private final GroupTimeSource timeSource;

	private final JdbcGroupMembershipRepository memberships;

	private final UserOperations users;

	DefaultGroupOperations(JdbcGroupRepository repository, TenantOperations tenants, GroupTimeSource timeSource,
			JdbcGroupMembershipRepository memberships, UserOperations users) {
		this.repository = repository;
		this.tenants = tenants;
		this.timeSource = timeSource;
		this.memberships = memberships;
		this.users = users;
	}

	@Override
	@Transactional
	public Group create(TenantId tenantId, CreateGroupRequest request) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(request, "Create group request must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		Instant now = this.timeSource.now();
		return this.repository.insert(new Group(GroupId.random(), tenantId, request.displayName(), GroupStatus.ACTIVE, 0,
				now, now));
	}

	@Override
	public Optional<Group> findById(TenantId tenantId, GroupId groupId) {
		return this.repository.findById(tenantId, groupId).filter(Group::isActive);
	}

	@Override
	@Transactional
	public Group updateDisplayName(TenantId tenantId, GroupId groupId, long expectedVersion, String displayName) {
		validateExpectedVersion(expectedVersion);
		this.tenants.requireActiveForWrite(tenantId);
		Group current = requireGroupForUpdate(tenantId, groupId);
		requireExpectedVersion(current, expectedVersion);
		Group changed = current.updateDisplayName(displayName, transitionTime(current));
		return changed == current ? current : this.repository.updateDisplayName(current, changed);
	}

	@Override
	@Transactional
	public Group delete(TenantId tenantId, GroupId groupId, long expectedVersion) {
		validateExpectedVersion(expectedVersion);
		this.tenants.requireActiveForWrite(tenantId);
		Group current = requireGroupForUpdate(tenantId, groupId);
		requireExpectedVersion(current, expectedVersion);
		Group changed = current.delete(transitionTime(current));
		if (changed == current) {
			return current;
		}
		this.memberships.findByGroup(tenantId, groupId)
			.stream()
			.map(GroupMembership::userId)
			.sorted(USER_ID_ORDER)
			.forEach(userId -> this.users.recordMembershipChangeForWrite(tenantId, userId));
		this.memberships.deleteByGroup(current);
		return this.repository.delete(current, changed);
	}

	@Override
	public Set<GroupMembership> findMembers(TenantId tenantId, GroupId groupId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(groupId, "Group ID must not be null");
		return this.memberships.findByActiveGroup(tenantId, groupId)
			.orElseThrow(() -> new GroupNotFoundException(tenantId, groupId));
	}

	@Override
	@Transactional
	public Group replaceMembers(TenantId tenantId, GroupId groupId, long expectedVersion, Set<UserId> memberIds) {
		validateExpectedVersion(expectedVersion);
		Objects.requireNonNull(memberIds, "Group member IDs must not be null");
		Set<UserId> desiredUserIds = Set.copyOf(memberIds);
		this.tenants.requireActiveForWrite(tenantId);
		Group current = requireGroupForUpdate(tenantId, groupId);
		requireExpectedVersion(current, expectedVersion);
		Set<GroupMembership> existing = this.memberships.findByGroup(tenantId, groupId);
		Set<UserId> existingUserIds = existing.stream().map(GroupMembership::userId).collect(Collectors.toUnmodifiableSet());
		if (existingUserIds.equals(desiredUserIds)) {
			desiredUserIds.stream().sorted(USER_ID_ORDER)
				.forEach(userId -> this.users.requireNotDeletedForWrite(tenantId, userId));
			return current;
		}
		Set<UserId> affectedUserIds = new HashSet<>(existingUserIds);
		affectedUserIds.addAll(desiredUserIds);
		affectedUserIds.stream().sorted(USER_ID_ORDER).forEach(userId -> {
			boolean membershipChanged = existingUserIds.contains(userId) != desiredUserIds.contains(userId);
			if (membershipChanged) {
				this.users.recordMembershipChangeForWrite(tenantId, userId);
			}
			else {
				this.users.requireNotDeletedForWrite(tenantId, userId);
			}
		});
		Instant changedAt = transitionTime(current);
		Group changed = current.membersChanged(changedAt);
		this.memberships.replace(current, existing, desiredUserIds, changedAt);
		return this.repository.updateMembers(current, changed);
	}

	private Group requireGroupForUpdate(TenantId tenantId, GroupId groupId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(groupId, "Group ID must not be null");
		return this.repository.findByIdForUpdate(tenantId, groupId)
			.filter(Group::isActive)
			.orElseThrow(() -> new GroupNotFoundException(tenantId, groupId));
	}

	private static void requireExpectedVersion(Group group, long expectedVersion) {
		if (group.version() != expectedVersion) {
			throw new GroupConcurrentUpdateException(group.tenantId(), group.id(), expectedVersion);
		}
	}

	private static void validateExpectedVersion(long expectedVersion) {
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected group version must not be negative");
		}
	}

	private Instant transitionTime(Group current) {
		Instant now = this.timeSource.now();
		return now.isBefore(current.updatedAt()) ? current.updatedAt() : now;
	}

}
