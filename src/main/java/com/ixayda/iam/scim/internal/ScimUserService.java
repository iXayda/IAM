package com.ixayda.iam.scim.internal;

import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;

@Service
final class ScimUserService {

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

	private static ResourceNotFoundException notFound() {
		return new ResourceNotFoundException(NOT_FOUND_DETAIL);
	}

}
