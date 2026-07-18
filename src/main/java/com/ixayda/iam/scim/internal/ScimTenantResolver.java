package com.ixayda.iam.scim.internal;

import com.ixayda.iam.tenant.TenantId;
import com.unboundid.scim2.common.exceptions.ResourceNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
final class ScimTenantResolver {

	private static final String NOT_FOUND_DETAIL = "The requested SCIM user was not found.";

	TenantId resolve(Jwt jwt) throws ResourceNotFoundException {
		try {
			return TenantId.from(jwt.getClaimAsString("tenant_id"));
		}
		catch (RuntimeException exception) {
			throw new ResourceNotFoundException(NOT_FOUND_DETAIL);
		}
	}

}
