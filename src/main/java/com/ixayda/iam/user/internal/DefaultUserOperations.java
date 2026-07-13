package com.ixayda.iam.user.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserConcurrentUpdateException;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserOperations;
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

	DefaultUserOperations(JdbcUserRepository repository, TenantOperations tenants, UserTimeSource timeSource) {
		this.repository = repository;
		this.tenants = tenants;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional
	public User create(TenantId tenantId, CreateUserRequest request) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(request, "Create user request must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		Instant now = this.timeSource.now();
		User user = new User(UserId.random(), tenantId, request.identifiers(), UserStatus.ACTIVE, 0, now, now, null);
		return this.repository.insert(user);
	}

	@Override
	public Optional<User> findById(TenantId tenantId, UserId userId) {
		return this.repository.findById(tenantId, userId);
	}

	@Override
	public Optional<User> findByLogin(TenantId tenantId, LoginKey loginKey) {
		return this.repository.findByLogin(tenantId, loginKey);
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
		return changeStatus(tenantId, userId, User::delete);
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
