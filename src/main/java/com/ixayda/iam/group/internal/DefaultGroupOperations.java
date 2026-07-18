package com.ixayda.iam.group.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupConcurrentUpdateException;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupNotFoundException;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultGroupOperations implements GroupOperations {

	private final JdbcGroupRepository repository;

	private final TenantOperations tenants;

	private final GroupTimeSource timeSource;

	DefaultGroupOperations(JdbcGroupRepository repository, TenantOperations tenants, GroupTimeSource timeSource) {
		this.repository = repository;
		this.tenants = tenants;
		this.timeSource = timeSource;
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
		return changed == current ? current : this.repository.delete(current, changed);
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
