package com.ixayda.iam.group.internal;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserDeletionParticipant;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
class GroupUserDeletionParticipant implements UserDeletionParticipant {

	private final JdbcGroupRepository groups;

	private final JdbcGroupMembershipRepository memberships;

	private final GroupTimeSource timeSource;

	GroupUserDeletionParticipant(JdbcGroupRepository groups, JdbcGroupMembershipRepository memberships,
			GroupTimeSource timeSource) {
		this.groups = groups;
		this.memberships = memberships;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public void beforeDelete(User user) {
		Objects.requireNonNull(user, "User must not be null");
		if (user.isDeleted()) {
			throw new IllegalArgumentException("User must not already be deleted");
		}
		for (GroupId groupId : this.memberships.findGroupIdsByUser(user.tenantId(), user.id())) {
			Group current = this.groups.findByIdForUpdate(user.tenantId(), groupId)
				.orElseThrow(() -> new IllegalStateException("Group membership references a missing group"));
			this.memberships.deleteForUser(current, user.id());
			if (current.isActive()) {
				Group changed = current.membersChanged(transitionTime(current));
				this.groups.updateMembers(current, changed);
			}
		}
	}

	private Instant transitionTime(Group current) {
		Instant now = this.timeSource.now();
		return now.isBefore(current.updatedAt()) ? current.updatedAt() : now;
	}

}
