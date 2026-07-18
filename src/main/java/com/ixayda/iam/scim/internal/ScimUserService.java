package com.ixayda.iam.scim.internal;

import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserAlreadyExistsException;
import com.ixayda.iam.user.UserDirectoryQuery;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserPage;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ResourceConflictException;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class ScimUserService {

	private static final String NOT_FOUND_DETAIL = "The requested SCIM user was not found.";

	private final TenantOperations tenants;

	private final UserOperations users;

	ScimUserService(TenantOperations tenants, UserOperations users) {
		this.tenants = tenants;
		this.users = users;
	}

	User find(TenantId tenantId, String userId) throws ResourceNotFoundException {
		UserId parsedId;
		try {
			parsedId = UserId.from(userId);
			if (!parsedId.toString().equals(userId)) {
				throw new IllegalArgumentException("SCIM user ID must use its canonical representation");
			}
			this.tenants.requireActive(tenantId);
		}
		catch (IllegalArgumentException | TenantDisabledException | TenantNotFoundException exception) {
			throw notFound();
		}
		User user = this.users.findById(tenantId, parsedId).orElseThrow(ScimUserService::notFound);
		if (user.isDeleted()) {
			throw notFound();
		}
		return user;
	}

	UserPage findPage(TenantId tenantId, UserDirectoryQuery query) throws ResourceNotFoundException, BadRequestException {
		try {
			this.tenants.requireActive(tenantId);
		}
		catch (TenantDisabledException | TenantNotFoundException exception) {
			throw notFound();
		}
		UserPage page = this.users.findDirectoryPage(tenantId, query);
		if (page.totalResults() > Integer.MAX_VALUE) {
			throw BadRequestException.tooMany("The SCIM User query matched too many resources.");
		}
		return page;
	}

	@Transactional(rollbackFor = com.unboundid.scim2.common.exceptions.ScimException.class)
	public User create(TenantId tenantId, ScimUserCreateRequest command)
			throws ResourceConflictException, ResourceNotFoundException {
		try {
			User created = this.users.create(tenantId, command.request());
			return command.active() ? created : this.users.disable(tenantId, created.id());
		}
		catch (UserAlreadyExistsException exception) {
			throw ResourceConflictException.uniqueness(
					"A SCIM User with the same login identifier already exists.");
		}
		catch (TenantDisabledException | TenantNotFoundException exception) {
			throw notFound();
		}
	}

	private static ResourceNotFoundException notFound() {
		return new ResourceNotFoundException(NOT_FOUND_DETAIL);
	}

}
