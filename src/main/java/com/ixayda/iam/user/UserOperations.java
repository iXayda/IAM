package com.ixayda.iam.user;

import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;

public interface UserOperations {

	User create(TenantId tenantId, CreateUserRequest request);

	Optional<User> findById(TenantId tenantId, UserId userId);

	/**
	 * Finds a user by tenant and canonical login key, independent of identifier type.
	 */
	Optional<User> findByLogin(TenantId tenantId, LoginKey loginKey);

	User activate(TenantId tenantId, UserId userId);

	User disable(TenantId tenantId, UserId userId);

	User lock(TenantId tenantId, UserId userId);

	/**
	 * Marks a user as deleted while retaining its reserved login identifiers.
	 */
	User delete(TenantId tenantId, UserId userId);

	User requireActive(TenantId tenantId, UserId userId);

	/**
	 * Requires an active user and holds a shared row lock for a write coordinated by
	 * the caller's existing read-write transaction.
	 */
	User requireActiveForWrite(TenantId tenantId, UserId userId);

	/**
	 * Requires an active user and holds an exclusive row lock for a write that must
	 * serialize all work coordinated through the same user.
	 */
	User requireActiveForUpdate(TenantId tenantId, UserId userId);

}
