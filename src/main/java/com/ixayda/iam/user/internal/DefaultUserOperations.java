package com.ixayda.iam.user.internal;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.ReplaceUserRequest;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserConcurrentUpdateException;
import com.ixayda.iam.user.UserDeletionParticipant;
import com.ixayda.iam.user.UserDirectoryQuery;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserPage;
import com.ixayda.iam.user.UserProfile;
import com.ixayda.iam.user.UserStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultUserOperations implements UserOperations {

	private final JdbcUserRepository repository;

	private final TenantOperations tenants;

	private final UserTimeSource timeSource;

	private final List<UserDeletionParticipant> deletionParticipants;

	DefaultUserOperations(JdbcUserRepository repository, TenantOperations tenants, UserTimeSource timeSource,
			List<UserDeletionParticipant> deletionParticipants) {
		this.repository = repository;
		this.tenants = tenants;
		this.timeSource = timeSource;
		this.deletionParticipants = List.copyOf(deletionParticipants);
	}

	@Override
	@Transactional
	public User create(TenantId tenantId, CreateUserRequest request) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(request, "Create user request must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		Instant now = this.timeSource.now();
		User user = new User(UserId.random(), tenantId, request.identifiers(), request.profile(), UserStatus.ACTIVE, 0, 0,
				now, now, null);
		return this.repository.insert(user);
	}

	@Override
	public Optional<User> findById(TenantId tenantId, UserId userId) {
		return this.repository.findById(tenantId, userId);
	}

	@Override
	public UserPage findDirectoryPage(TenantId tenantId, UserDirectoryQuery query) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(query, "User directory query must not be null");
		return this.repository.findDirectoryPage(tenantId, query);
	}

	@Override
	public Optional<User> findByLogin(TenantId tenantId, LoginKey loginKey) {
		return this.repository.findByLogin(tenantId, loginKey);
	}

	@Override
	@Transactional
	public User updateProfile(TenantId tenantId, UserId userId, long expectedVersion, UserProfile profile) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(profile, "User profile must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected user version must not be negative");
		}
		this.tenants.requireActiveForWrite(tenantId);
		User current = this.repository.findByIdForUpdate(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		if (current.version() != expectedVersion) {
			throw new UserConcurrentUpdateException(tenantId, userId, expectedVersion);
		}
		User changed = current.updateProfile(profile, transitionTime(current));
		return changed == current ? current : this.repository.updateProfile(current, changed);
	}

	@Override
	@Transactional
	public User replace(TenantId tenantId, UserId userId, long expectedVersion, ReplaceUserRequest request) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(request, "Replace user request must not be null");
		if (expectedVersion < 0) {
			throw new IllegalArgumentException("Expected user version must not be negative");
		}
		this.tenants.requireActiveForExclusiveWrite(tenantId);
		User current = this.repository.findByIdForUpdate(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		if (current.isDeleted()) {
			throw new UserNotFoundException(tenantId, userId);
		}
		if (current.version() != expectedVersion) {
			throw new UserConcurrentUpdateException(tenantId, userId, expectedVersion);
		}
		User changed = current.replace(request, transitionTime(current));
		return changed == current ? current : this.repository.replace(current, changed);
	}

	@Override
	public User requireActive(TenantId tenantId, UserId userId) {
		this.tenants.requireActive(tenantId);
		return requireActive(requireUser(tenantId, userId));
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = { TenantDisabledException.class, TenantNotFoundException.class,
					UserNotActiveException.class, UserNotFoundException.class })
	public User requireActiveForWrite(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		User user = this.repository.findByIdForShare(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		return requireActive(user);
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public User requireActiveForUpdate(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		User user = this.repository.findByIdForUpdate(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		return requireActive(user);
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = { TenantDisabledException.class, TenantNotFoundException.class,
					UserNotFoundException.class })
	public User requireNotDeletedForWrite(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		User user = this.repository.findByIdForShare(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		if (user.isDeleted()) {
			throw new UserNotFoundException(tenantId, userId);
		}
		return user;
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public User recordMembershipChangeForWrite(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		User current = this.repository.findByIdForUpdate(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		if (current.isDeleted()) {
			throw new UserNotFoundException(tenantId, userId);
		}
		User changed = current.membershipsChanged(transitionTime(current));
		return this.repository.updateMemberships(current, changed);
	}

	@Override
	@Transactional
	public User activate(TenantId tenantId, UserId userId) {
		return changeStatus(tenantId, userId, User::activate);
	}

	@Override
	@Transactional
	public User disable(TenantId tenantId, UserId userId) {
		return changeStatus(tenantId, userId, User::disable);
	}

	@Override
	@Transactional
	public User lock(TenantId tenantId, UserId userId) {
		return changeStatus(tenantId, userId, User::lock);
	}

	@Override
	@Transactional
	public User delete(TenantId tenantId, UserId userId) {
		this.tenants.requireActiveForExclusiveWrite(tenantId);
		User current = this.repository.findByIdForUpdate(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		User changed = current.delete(transitionTime(current));
		if (changed == current) {
			return current;
		}
		this.deletionParticipants.forEach(participant -> participant.beforeDelete(current));
		return this.repository.updateStatus(current, changed);
	}

	private User changeStatus(TenantId tenantId, UserId userId, BiFunction<User, Instant, User> transition) {
		this.tenants.requireActiveForWrite(tenantId);
		User current = requireUser(tenantId, userId);
		User changed = transition.apply(current, transitionTime(current));
		return changed == current ? current : updateStatus(current, changed);
	}

	private User updateStatus(User current, User changed) {
		try {
			return this.repository.updateStatus(current, changed);
		}
		catch (UserConcurrentUpdateException ex) {
			User latest = requireUser(current.tenantId(), current.id());
			if (latest.status() == changed.status()) {
				return latest;
			}
			throw ex;
		}
	}

	private Instant transitionTime(User current) {
		Instant now = this.timeSource.now();
		return now.isBefore(current.updatedAt()) ? current.updatedAt() : now;
	}

	private User requireUser(TenantId tenantId, UserId userId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		return this.repository.findById(tenantId, userId)
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
	}

	private User requireActive(User user) {
		if (!user.isActive()) {
			throw new UserNotActiveException(user.tenantId(), user.id(), user.status());
		}
		return user;
	}

}
